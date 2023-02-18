import os
import sys
from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex #Call these functions from log_analysis
import pandas as pd  #Import pandas for csv file creation and codename it as pd
import re #Import regex

def main():
    
    log_file = get_log_file_path_from_cmd_line(1)  #We get the log file by calling the function at getting the first item in the return statement
    port_traffic = tally_port_traffic(log_file)    #Make a tally of port traffic
    generate_invalid_user_report(log_file)       #Generate a list of invalid users
    generate_source_ip_log(log_file, ip_address='220.195.35.40')  #Make a source IP log using the IP address provided

    for port_num, count in port_traffic.items():     #Count the number of items in the log file
        if count >= 100:                              #If the number is over 100, generate a traffic report
            generate_port_traffic_report(log_file, port_num)
    pass

def tally_port_traffic(log_file):

    data = filter_log_by_regex(log_file, r'DPT=(.+?) ')[1]     #Filter the log content by the destination port only
    port_traffic = {}
    for d in data :
        port = d[0]    #Add each found item to the port traffic dictionary
        port_traffic[port] = port_traffic.get(port, 0) + 1  
    return port_traffic

def generate_port_traffic_report(log_file, port_number):

    regex = r'(.{6}) (.{8}) .*SRC=(.+) DST=(.+?) .*SPT=(.+) ' + f'DPT=({port_number})'      #This regex filters and nabs only the SRC, Destination and Destination Port
    data = filter_log_by_regex(log_file, regex)[1] #We get the data by using the filtered log function in lab_analysis
    report_df = pd.DataFrame(data) #Create a data frame
    headers = ('DATE', 'TIME', 'Source Ip Address', 'Destination IP Address', 'Source Port', 'Destination Port')
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False, header=headers)
    #Create a CSV file with the port number and the headers created above
    return

# TODO: Step 11
def generate_invalid_user_report(log_file):
    
    regex = r'(.{6}) (.{8}).*Invalid user (.*) from (.*)'   #This regex will get only the Invalid user and source IP from the logs
    data = filter_log_by_regex(log_file, regex)[1]
    report_df = pd.DataFrame(data)                       #Create a csv file
    headers = ('Date', 'Time', 'Username', 'IP Address')  #Import the headers in
    report_df.to_csv(f'invalid_users.csv', index=False, header=headers)
        #And the file is created
    return 

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):

    regex = rf'(.*SRC={ip_address}.*)' #Grab only the SRC field
    data = filter_log_by_regex(log_file, regex)[1]
    report_df = pd.DataFrame(data)             #Create a csv file to put the IPs in
    ip_address = re.sub(r'\.', '_', ip_address) #Replace all /. with an underscore
    report_df.to_csv(f'source_ip_{ip_address}.log', index=False, header=False)
    #And create the log
    return

if __name__ == '__main__':
    main()