import os
import sys
import subprocess

def measure_perf(cmd):
    # Run command
    out = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

    # Get output
    stdout, _ = out.communicate()

    # Check if start of output is a number
    try:
        num = float(stdout.split(b';')[0])
    except ValueError:
        return -1

    # Get running time in ms
    return num

def measure_trace(cmd):
    # Run command
    out = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

    # Get output
    stdout, _ = out.communicate()

    tokens = stdout.split(b'\n')

    # Check if start of output is a number
    try:
        if not tokens[0].startswith(b'<RET'):
            raise ValueError('Did not finish trace successfully')
        time_td = float(tokens[1])
        time_t = float(tokens[2])+float(tokens[3])
        time_d = float(tokens[4])
    except (ValueError, IndexError) as e:
        print(e, file=sys.stderr)
        print(str(cmd) + '\n' + str(stdout), file=sys.stderr)
        return [-1, -1, -1]

    # Get running time in ms
    return [time_td, time_t, time_d]

# Get current working directory path
path = os.getcwd()

# Populate buf_size map
# Lo-complexity
buf_sizes = {
    1000: 2,
    2000: 4,
    3000: 8,
    6000: 16,
    12000: 32,
    24000: 64,
    48000: 128,
    96000: 256,
    190000: 512,
    380000: 1024,
    760000: 2048
}
buf_size = 0

# Print header
# iterations out-of-context;
print("iterations;buffer size;without trace;with trace;overhead ratio;trace time;decode time")

for i in range(5):
    for j in range(999, 1000000, 1000):
        it_out = pow(10, i)
        it_in = j+1

        # Set arguments
        args = [str(it_in), str(it_out)]

        # Set buffer size
        buf_size = buf_sizes.get(it_in, buf_size)
        if buf_size == 0:
            buf_size = 1024

        # Set up commands
        perf_cmd = ['perf', 'stat', '-x', ';']
        target_cmd = path+'/bin/t7'
        # target_cmd = path+'/bin/t8'
        cmd = perf_cmd+[target_cmd]+args
        trace_cmd = [path+'/bin/tracer',
            '-q',
            '-t',
            str(buf_size),
            ' '.join([target_cmd]+args),
            'main']

        time_notrace = -1
        time_td = -1
        time_t = -1
        time_d = -1
        overhead = -1

        # Measure runtime with and without tracing
        while time_notrace < 0:
            time_notrace = measure_perf(cmd)
        while time_td < 0 or time_t < 0 or time_d < 0 or overhead < 0:
            [time_td, time_t, time_d] = measure_trace(trace_cmd)
            overhead = ((time_td-time_notrace)/time_notrace)*100

        print(str(it_in)+';'
            +str(it_out)+';'
            +str(buf_size)+';'
            +str(time_notrace)+';'
            +str(time_td)+';'
            +str(overhead)+'%;'
            +str(time_t)+';'
            +str(time_d),
            flush=True)