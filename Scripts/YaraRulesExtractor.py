# YaraRulesExtractor.py

# Author: Idan-Beit-Yosef @ IBYf0r3ns1cs

import re
import os

print(r"""
_____.___.  _____ __________    _____    ___________         __                        __                
\__  |   | /  _  \\______   \  /  _  \   \_   _____/__  ____/  |_____________    _____/  |_  ___________ 
 /   |   |/  /_\  \|       _/ /  /_\  \   |    __)_\  \/  /\   __\_  __ \__  \ _/ ___\   __\/  _ \_  __ \
 \____   /    |    \    |   \/    |    \  |        \>    <  |  |  |  | \// __ \\  \___|  | (  <_> )  | \/
 / ______\____|__  /____|_  /\____|__  / /_______  /__/\_ \ |__|  |__|  (____  /\___  >__|  \____/|__|   
 \/              \/       \/         \/          \/      \/                  \/     \/                    

Author: IBYf0r3ns1cs
""")


# Get the YARA rules file path from the user
yara_file_path = input("Path to yar file: ")

# Check if the file exists in the specified path
while not os.path.isfile(yara_file_path):
    print("File not found.")
    yara_file_path = input("Please enter a valid path to the yar file: ")

# Get the output folder path from the user
output_folder_path = input("Please enter a folder path to extract the YARA rules to: ")

# Open the YARA rules file
with open(yara_file_path, "r") as yara_file:
    yara_rules = yara_file.read()

# Split the YARA rules by "rule" keyword
rules_list = re.split(r"rule\s+", yara_rules)

# Remove any empty strings
rules_list = [rule for rule in rules_list if rule]

# Loop through each rule and write it to a separate file
for rule in rules_list:
    # Extract the rule name from the rule body and remove any invalid characters
    rule_name = re.sub(r"[^\w_]", "", rule.split("{")[0].strip())
    
    # Create a new file for the rule and write the rule to it
    with open(os.path.join(output_folder_path, f"{rule_name}.yar"), "w") as rule_file:
        rule_file.write(f"rule {rule}")
        
print("YARA rules have been successfully extracted.")


