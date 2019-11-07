from datetime import datetime
from dateutil.parser import parse
from collections import OrderedDict
from collections import defaultdict
from pandas import read_csv
import csv
import numpy as np
import matplotlib.pyplot as plt	

inputFile = "features_dataset_10_09_2019_21h20min.txt"

lis = list(csv.reader(open(inputFile)))
list_announcements = lis[-60:]

print inputFile

#print lis[-1] # prints final line as a list of strings

mrai = 0

announcement_file = "features_dataset.csv"
csv = open(announcement_file,"w")
columnF = "num_announcements, num_withdrawals, duplicate_announce, longest_aspath, shortest_aspath, avg_as_path, num_prepended_ases, tlong_events, tshort_events, avg_edit_distance, max_edit_distance, num_edited_paths, rare_as1, rare_as2, rare_as3, rare_as4, rare_as5, event_type, mrai\n"
csv.write(columnF)
csv.close()

csv = open(announcement_file,"a")
						
for line in list_announcements:
        #dict_file = list(line)
	#print(dict_file[0])
	#new_line = line.split(",")
	#print "line"
	str_line = ""
	for i in range(0,len(line)):
		if i == 0: 
			line2 = line[i].split('[')
			line3 = line2[1].split(' ')
			#print line3[0]
			str_line = str_line + str(line3[0])
			str_line = str_line + ","
		if i == len(line)-1:
			line2 = line[i].split(']')
			line3 = line2[0].split(' ')
			#print line3[1]
			str_line = str_line + str(line3[1])
			str_line = str_line + "," + str(mrai) + "\n"
		if i != 0 and i != len(line)-1: 
			#print "i" + str(i)
			#print line[i]
			str_line = str_line + str(line[i])
			str_line = str_line + ","
	#print "str_line:"
	#print str_line
	csv.write(str_line)

csv.close()
			

