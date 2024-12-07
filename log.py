import re
from collections import defaultdict, Counter

# File paths
input_file = "sample.log"
csv_output_file = "result.csv"
log_output_file = "results.log"

# Regex pattern to parse log entries
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>.*?)\] "(?P<method>GET|POST) (?P<endpoint>.*?) HTTP/1.1" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>.*?)")?'
)

# Dictionaries to store data
request_counts = Counter()
endpoint_counts = Counter()
failed_login_attempts = defaultdict(int)

# Process log file
with open(input_file, "r") as f:
    for line in f:
        match = log_pattern.match(line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint")
            status = match.group("status")

            # Count requests per IP
            request_counts[ip] += 1

            # Count accesses per endpoint
            endpoint_counts[endpoint] += 1

            # Count failed login attempts (status code 401)
            if status == "401":
                failed_login_attempts[ip] += 1

# Get the most accessed endpoint
most_accessed_endpoint, access_count = endpoint_counts.most_common(1)[0]

# Write results.csv
with open(csv_output_file, "w") as csv_file:
    # Write requests per IP
    csv_file.write("IP Address,Request Count\n")
    for ip, count in request_counts.most_common():
        csv_file.write(f"{ip},{count}\n")
    
    # Write the most accessed endpoint
    csv_file.write("\nMost Frequently Accessed Endpoint\n")
    csv_file.write(f"Endpoint,Access Count\n")
    csv_file.write(f"{most_accessed_endpoint},{access_count}\n")
    
    # Write suspicious activity
    csv_file.write("\nSuspicious Activity Detected\n")
    csv_file.write("IP Address,Failed Login Attempts\n")
    for ip, attempts in failed_login_attempts.items():
        csv_file.write(f"{ip},{attempts}\n")

# Write results.log
with open(log_output_file, "w") as log_file:
    # Write requests per IP
    log_file.write("Requests per IP:\n")
    log_file.write("IP Address          Request Count\n")
    log_file.write("-----------------------------------\n")
    for ip, count in request_counts.most_common():
        log_file.write(f"{ip:<20} {count:<15}\n")
    
    # Write the most accessed endpoint
    log_file.write("\nMost Frequently Accessed Endpoint:\n")
    log_file.write(f"{most_accessed_endpoint} (Accessed {access_count} times)\n")
    
    # Write suspicious activity
    log_file.write("\nSuspicious Activity Detected:\n")
    log_file.write("IP Address          Failed Login Attempts\n")
    log_file.write("----------------------------------------\n")
    for ip, attempts in failed_login_attempts.items():
        log_file.write(f"{ip:<20} {attempts:<15}\n")
