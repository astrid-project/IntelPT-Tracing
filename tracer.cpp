#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <chrono>

#include <unistd.h>
#include <syscall.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <cpuid.h>

#include "lib/load_elf.h"
#include "ptxed_util.cpp"

using namespace std;

// Variables for internal timing
chrono::high_resolution_clock::time_point total_start,
                                          total_finish,
                                          tsetup_start,
                                          tsetup_finish,
                                          trace_start,
                                          trace_finish,
                                          decode_start,
                                          decode_finish;

bool verbose = false;
bool quiet = false;
bool timing = false;

int FD;
char* TARGET_CMD;
pid_t TARGET_PID;

// The DATA region is not used in this application
size_t DATA_SIZE = 0;
size_t AUX_SIZE = 0x800;

struct gm_file_link
{
    string filename;
    uint64_t base;
};

void report_error(int err)
{
    printf("ERROR %d: %s\n", err, pt_errstr(pt_errcode(err)));
}

static void sigchld_handler(int sig)
{
    trace_finish = chrono::high_resolution_clock::now();
}

/**
 * This function uses the GCC __get_cpuid method to determine
 * the family, model and stepping values for the processor
 * it is running on and applies them to the IPT config. This
 * is required for the libipt workaround for erratum SKL014:
 * Intel(R) PT TIP.PGD May Not Have Target IP Payload.
 */
void cpu_info(pt_config *config)
{
    unsigned level = 1, eax = 0, ebx, ecx, edx;

    __get_cpuid(level, &eax, &ebx, &ecx, &edx);

    config->cpu.vendor = pcv_intel; // We assume this to be the case
    config->cpu.family = (((eax >> 20) & 0xFF) << 4) + ((eax >> 8) & 0xF);
    config->cpu.model = (((eax >> 16) & 0xF) << 4) + ((eax >> 4) & 0xF);
    config->cpu.stepping = eax & 0xF;

    // Validate settings
    int errcode = pt_cpu_errata(&config->errata, &config->cpu);

    if (errcode < 0)
    {
        printf("[0, 0: config error: %s]\n",
                  pt_errstr(pt_errcode(errcode)));

        printf("\tfamily %d\n", config->cpu.family);
        printf("\tmodel %d\n", config->cpu.model);
        printf("\tstepping %d\n", config->cpu.stepping);
    }
}

/**
 * This function parses the filter command line argument and
 * initializes the trace context accordingly. The filter string
 * can be a symbol name or range of address offsets on the form
 * 0x<start>-0x<end> in the target executable.
 */
static int parse_context(gm_trace_context *context, char *arg)
{
    string range = arg;
    // Check whether the argument is a range
    uint32_t sep = range.find('-');

    // If the argument is a function name, simply set it and return 0
    if (sep == -1)
    {
        context->function = arg;
    }
    // If the argument is a range of addresses, parse them into the context
    else
    {
        stringstream ss;

        // Parse the start address
        ss << hex << range.substr(0, sep);
        ss >> context->start;
        ss.clear();
        
        // Parse the end address
        ss << hex << range.substr(sep+1, range.length());
        ss >> context->end;
    }

    return 0;
}

static char **parse_cmd(char *arg)
{
    vector <char *> ret;
    string argstr = arg;
    int pos = argstr.find(' '), num = 0;
    char *cstr;

    TARGET_CMD = new char[pos == -1 ? argstr.length() : pos];
    strcpy(TARGET_CMD, argstr.substr(0, pos).c_str());
    ret.push_back(TARGET_CMD);
    
    while (pos > 0)
    {
        int start = pos+1;
        pos = argstr.find(' ', start);
        
        cstr = new char [(pos == -1 ? argstr.length() : pos)-start];
        strcpy(cstr, argstr.substr(start, pos-start).c_str());

        ret.push_back(cstr);
    }

    ret.push_back(NULL);

    return &ret[0];
}

/**
 * This function parses the maps file for the target process
 * and returns the number of mapped executable file sections.
 * If save is set to a non-zero value, it also stores each
 * section's file name and base address in a vector.
 */
static int get_linked_files(vector<gm_file_link> *links,
                            gm_trace_context *context, bool save)
{
	int status, cnt = 0;
    string line;
	char *filename = new char[32];
    // Determine the maps filename of target process
	sprintf(filename, "/proc/%d/maps", TARGET_PID);

    // Open file stream on maps filename
	ifstream mapsfile(filename);

    while (getline(mapsfile, line))
    {
        int lsplit, rlen;
        unsigned long startaddr;
        string acc, target;
        stringstream ss;

        // Get base address of section
        lsplit = 0;
        rlen = line.find('-', lsplit+1)-lsplit;
        ss.clear();
        ss << hex << line.substr(lsplit, rlen);
        ss >> startaddr;

        // Get end address of section
        lsplit = lsplit+rlen+1;
        rlen = line.find(' ', lsplit+1)-lsplit;

        // Get access control flags
        lsplit = lsplit+rlen+1;
        rlen = line.find(' ', lsplit+1)-lsplit;
        acc = line.substr(lsplit, rlen);

        // Skip non-executable sections
        if (acc.find('x') != -1)
        {
            // Get section identifier
            lsplit = line.find_last_of(' ')+1;
            target = line.substr(lsplit);

            // Skip non-filename identifiers
            if (target.length() > 0 && target[0] != '[')
            {
                cnt++;

                // Only save the results if parameter is set
                // and current target is main executable if
                // context is set
                if (save && ((context->function == NULL
                    && context->end == 0)
                    || target.compare(TARGET_CMD) == 0))
                {
                    // Compute library load offset
                    uint64_t offset;
                    elf_load_offset(target.c_str(), startaddr, &offset,
                                    TARGET_CMD, target.compare(TARGET_CMD) == 0
                                        ? context : NULL);

                    // Add the file information to links
                    gm_file_link link;
                    link.filename = target;
                    link.base = offset;
                    links->push_back(link);
                }
            }
        }
    }

    mapsfile.close();

    return cnt;
}

/**
 * This function trims leading whitespace from a string
 */
char *trim_str(char *str)
{
    // Keep iterating the string pointer untilit points to a
    // non-whitespace character (possibly the null terminator)
    while(isspace(str[0]))
    {
        str++;
    }

    return str;
}

/**
 * This function uses the ldd command line tool to
 * count the expected number of loaded runtime
 * libraries for the target executable.
 */
int libcount()
{
    string data;
    FILE * stream;
    const int max_buffer = 256;
    char buffer[max_buffer];
    char cmd[max_buffer];
    int cnt = 0;

    // run ldd and capture output as FILE
    sprintf(cmd, "ldd %s 2>&1",TARGET_CMD);
    stream = popen(cmd, "r");

    if (stream)
    {
        while (!feof(stream))
        {
            if (fgets(buffer, max_buffer, stream) != NULL)
            {
                // Trim leading whitespace from line
                char *line = trim_str(buffer);
                
                // Count all literal file paths
                if (line[0] == '/')
                {
                    cnt++;
                }
                // Count all symbolic links to file paths
                else
                {
                    // Identify the target of the symbolic link
                    strtok(line, " => ");
                    strtok(NULL, " ");
                    char *token = strtok(NULL, " ");

                    // Check whether target is literal file path
                    if (token != NULL && token[0] == '/')
                    {
                        cnt++;
                    }
                }
            }
        }

        // Close FILE
        pclose(stream);
    }

    // Add one for the main executable
    return cnt+1;
}

/**
 * This function steps through the target process
 * block-by-block until it has mapped the expected
 * number of external libraries and stores the list.
 */
void monitor_maps(vector<struct gm_file_link> *links,
                  gm_trace_context *context)
{
    // Determine the expected number of linked libraries
    // Should be exactly 1 if context is set
    int mapcnt, libcnt = context->function == NULL
                        && context->end == 0 ? libcount() : 1;

    // Skip the loop if expecting only 1 link
    if (libcnt > 1)
    {
        // While the actual number of linked libraries is
        // less than the expected number, keep checking
        do
        {
            // Step child process one block forward
            ptrace(PTRACE_SINGLEBLOCK, TARGET_PID);

            // Check current number of linked libraries
            mapcnt = get_linked_files(links, context, false);
        } while (mapcnt < libcnt);
    }

    // Load the linked libraries
    get_linked_files(links, context, true);
}

/**
 * This function takes the stored list of mapped libraries
 * and loads them into the decoder.
 */
static int load_image(
         vector<gm_file_link> *links,
         ptxed_decoder *decoder,
         pt_image *image,
         char* prog)
{
    int status;

    if (verbose)
    {
        printf("Loading linked libraries into decoder image...\n");
    }

    // Loop through the saved linked libraries
    for (int i = 0; i < links->size(); i++)
    {
        gm_file_link *cur = &((*links)[i]);

        int len = cur->filename.size()+1;
        char *cfilename = new char[len];
        strcpy(cfilename, cur->filename.c_str());

        if (verbose)
        {
            printf("+   %s: base=0x%lx\n", cur->filename.c_str(), cur->base);
        }

        // Load the file at the appropriate offset
        status = load_raw(decoder->iscache, image, cfilename, cur->base, prog);
    }

	return status;
}

/**
 * This function obtains a PERF event file descriptor,
 * allocates and maps the memory buffer for Intel PT
 * to write its output for the target process.
 */
perf_event_mmap_page* alloc_pt_buf()
{
    struct perf_event_attr attr;

    if (verbose)
    {
        printf("Allocating buffer for IPT...\n");
    }

    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.exclude_kernel = 1;
    attr.disabled = 1;
    
    // Read IPT PMU type from system file
    ifstream typeFile;
    typeFile.open("/sys/bus/event_source/devices/intel_pt/type");
    typeFile >> attr.type;
    typeFile.close();

    // Open perf event counter
    FD = syscall(SYS_perf_event_open, &attr, TARGET_PID, -1, -1, 0);

    struct perf_event_mmap_page *header;
    void *base, *aux;

    // Map DATA region to memory and assign the base pointer
    base = mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_SHARED, FD, 0);
    if (base == MAP_FAILED)
    {
        printf("Failed to allocate BASE\n");
        exit(EXIT_FAILURE);
    }

    header = (perf_event_mmap_page *)base;
    header->aux_offset = header->data_offset + header->data_size;
    header->aux_size = AUX_SIZE * PAGE_SIZE;
    
    // Map AUX region to memory
    aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, FD, header->aux_offset);
    if (aux == MAP_FAILED)
    {
        printf("Failed to allocate AUX\n");
        exit(EXIT_FAILURE);
    }

    header->aux_head = (uint64_t)aux;
    header->aux_tail = header->aux_head + header->aux_size;

    if (verbose)
    {
        printf("+   AUX: 0x%llx-0x%llx (%llu bytes)\n",
                header->aux_head, header->aux_tail, header->aux_size);
    }

    return header;
}

int main(int argc, char** argv)
{
    // Start the trace setup timer
    total_start = chrono::high_resolution_clock::now();
    tsetup_start = total_start;

    vector<struct gm_file_link> links;
    gm_trace_context context;

    int argi = 1;

    // Verbose flag
    if (strcmp(argv[argi++], "-v") == 0)
    {
        verbose = true;
    }
    else
    {
        argi--;
    }

    // Quiet flag
    if (strcmp(argv[argi++], "-q") == 0)
    {
        quiet = true;
    }
    else
    {
        argi--;
    }

    // Timer flag
    if (strcmp(argv[argi++], "-t") == 0)
    {
        timing = true;
    }
    else
    {
        argi--;
    }

    // Buffer size
    AUX_SIZE = atol(argv[argi++]);

    // Check for mandatory args
    if (argc < argi+1)
    {
        fprintf(stderr, "Invalid args.\n");
        return 1;
    }

    // Target command
    vector <char *> command;
    string argstr = argv[argi++];
    int pos = argstr.find(' ');
    char *cstr;

    TARGET_CMD = new char[pos == -1 ? argstr.length() : pos];
    strcpy(TARGET_CMD, argstr.substr(0, pos).c_str());
    command.push_back(TARGET_CMD);

    while (pos > 0)
    {
        int start = pos+1;
        pos = argstr.find(' ', start);
        cstr = new char [(pos == -1 ? argstr.length() : pos)-start];
        strcpy(cstr, argstr.substr(start, pos-start).c_str());

        command.push_back(cstr);
    }

    command.push_back(NULL);

    // Target context (optional). Can be a function name
    // or a range of address offsets
    if (argc > argi)
    {
        parse_context(&context, argv[argi++]);
    }
    
    // Fork a new child process to run the target executable
    TARGET_PID = fork();

    // Start target executable in child process
    if (TARGET_PID == 0)
    {
        // Pause execution of child process on exec pending decoder setup
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // Execute target
        execve(TARGET_CMD, &command[0], environ);
        // If this command runs something has gone terribly wrong
        exit(1);
    }

    struct perf_event_mmap_page* header;
    int	childstatus;

    // Make sure the target is stopped before proceeding
    waitpid(TARGET_PID, &childstatus, 0);

    // If everything went right, the target process should have hit a breakpoint
    if (WIFSTOPPED(childstatus) && WSTOPSIG(childstatus) == SIGTRAP)
    {
        // Allocate memory buffer for IPT
        header = alloc_pt_buf();
        // Populate list of linked libraries
        monitor_maps(&links, &context);

        if (verbose && context.end > 0)
        {
            printf("Context filtering enabled...\n"
                    "+   function:\t%s\n"
                    "+   start:\t0x%lx\n"
                    "+   end:\t0x%lx\n",
                context.function,
                context.base+context.start,
                context.base+context.end);
        }

        // Generate IP filter string for specified range/method
        char filterstr[128];
        if (context.end > 0)
        {
            snprintf(filterstr, 128, "filter 0x%lx/%lu@%s",
                context.start,
                context.end-context.start,
                TARGET_CMD);
        }

        // Tell child process to proceed
        ptrace(PTRACE_CONT, TARGET_PID);
        ptrace(PTRACE_DETACH, TARGET_PID);

        // Apply IP filter
        if (context.end > 0)
        {
            ioctl(FD, PERF_EVENT_IOC_SET_FILTER, filterstr);
        }
        
        // Enable Intel PT recording
        ioctl(FD, PERF_EVENT_IOC_ENABLE);

        // Stop the trace setup timer and start the trace timer
        tsetup_finish = chrono::high_resolution_clock::now();
        trace_start = tsetup_finish;
        // Also start the decoder timer
        decode_start = trace_start;

        // Assign the SIGCHLD handler
        signal(SIGCHLD, sigchld_handler);
    }

	struct ptxed_decoder decoder;
	struct ptxed_options options;
	struct ptxed_stats stats;
	struct pt_config config;
	struct pt_image *image;
	int errcode;

    // Default decoder options and stats to 0
    memset(&options, 0, sizeof(options));
	memset(&stats, 0, sizeof(stats));

    // Initialize decoder
	errcode = ptxed_init_decoder(&decoder);
	if (errcode < 0)
    {
		report_error(errcode);
        exit(1);
	}

    // Allocate traced memory image
	image = pt_image_alloc(NULL);
	if (!image)
    {
		fprintf(stderr, "%s: failed to allocate image.\n", TARGET_CMD);
        exit(1);
	}

    // Set decoder options
    options.quiet = quiet;
    // options.track_blocks = 1;

    // Load linked libraries into decoder image
    errcode = load_image(&links, &decoder, image, TARGET_CMD);
    if (errcode < 0)
    {
        report_error(errcode);
        exit(1);
    }

    // Set up decoder configuration to use the allocated PT buffer
	pt_config_init(&config);
    config.begin = (uint8_t *)header->aux_head;
    config.end = (uint8_t *)header->aux_tail;

    // We must set the correct cpu and specify the IP filtering
    // config to avoid the issue described in Intel erratum SKL014
    cpu_info(&config);

    if (context.end > 0)
    {
        config.addr_filter.config.ctl.addr0_cfg = 1;
        config.addr_filter.addr0_a = context.start;
        config.addr_filter.addr0_b = context.end;
    }

    // Allocate the decoder using the specified options and config
    alloc_decoder(&decoder, &config, image, &options, TARGET_CMD);
	if (!ptxed_have_decoder(&decoder))
    {
		fprintf(stderr, "%s: no pt.\n", TARGET_CMD);
		exit(1);
	}

    // Initialize Intel XED tables for instruction decoding
    xed_tables_init();

    // Set stats flags from options
	if (options.print_stats && !stats.flags)
    {
		stats.flags |= ptxed_stat_insn;

		if (decoder.type == pdt_block_decoder)
        {
			stats.flags |= ptxed_stat_blocks;
        }
	}

    // Start decoding
    if (verbose && !quiet)
    {
        printf("===== TRACE START =====\n");
    }
    decode(&decoder, &options, &stats, TARGET_PID);
    // Stop the decode timer
    decode_finish = chrono::high_resolution_clock::now();
    if (verbose && !quiet)
    {
        printf("====== TRACE END ======\n");
    }

    // Disable and close the PERF event listener
    ioctl(FD, PERF_EVENT_IOC_DISABLE);
    close(FD);

    // Print stats
	if (options.print_stats)
    {
		print_stats(&stats);
    }

    // Stop the total timer
    total_finish = chrono::high_resolution_clock::now();

    if (timing)
    {
        // Print timers
        chrono::duration<double> total_d = total_finish - total_start;
        chrono::duration<double> tsetup_d = tsetup_finish - tsetup_start;
        chrono::duration<double> trace_d = trace_finish - trace_start;
        chrono::duration<double> decode_d = decode_finish - decode_start;
        cout << total_d.count()*1000 << "\n";
        cout << tsetup_d.count()*1000 << "\n";
        cout << trace_d.count()*1000 << "\n";
        cout << decode_d.count()*1000 << "\n";
    }

    return 0;
}