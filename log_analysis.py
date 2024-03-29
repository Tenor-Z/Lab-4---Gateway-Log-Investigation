
import sys
import os
import re

def get_log_file_path_from_cmd_line(param_num):
    """Get the full path of a log file from the command line.
    Args:
        param_num (int): Parameter Number
    Returns:
        str: Full path of the log file. 
    """
    num_params = len(sys.argv) -1       #Get the number of parameters by going to the end of the length
    if num_params >= param_num:   #If the number of parameters is greater or equal
        log_file_path = sys.argv[param_num]  #Create the argv with the parameter of numbers
        if os.path.isfile(log_file_path):   #Check if file path is valid (is it an actual file)
            return os.path.abspath(log_file_path)
        else:
            print('Error: Specified path is not a file.')
            sys.exit(1)
    else:
        print('Error: Missing log file path.')
        sys.exit(1)


def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex.
    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.
    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    records = []
    captured_data = []

    regex_flags = re.IGNORECASE if ignore_case else 0 

    with open(log_file, 'r') as file:  # Iterate through file line by line
        for line in file: # Check line for regex match
            match = re.search(regex, line, regex_flags)
            if match:
                records.append(line)
                if match.lastindex:
                    captured_data.append(match.groups())


    if print_records is True:
        print(*records, sep='', end='\n')

    if print_summary is True:
        print(f'The log file contains {len(records)} records that case- {"in" if ignore_case else ""} sensitive match the regex"{regex}". ')


    
    return records, captured_data