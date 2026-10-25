########################
import json
########################

with open("security_log.json", "r") as file:
       for line in file: 
        data = json.loads(line)
        print(data)