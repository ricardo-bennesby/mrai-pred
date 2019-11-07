from datetime import datetime
from dateutil.parser import parse
from collections import OrderedDict
from collections import defaultdict
from pandas import read_csv
import csv
import numpy as np
import matplotlib.pyplot as plt	


list_mrais_10_09 = [5]
list_mrais_11_09 = [15,30,1]
list_mrais_12_09 = [15,5,1,30,5]
list_mrais_13_09 = [5,15,30,1,1,5,15]
list_mrais_14_09 = [30,1,5,15,30,1,15]
list_mrais_15_09 = [5,1,30,30,15,1,5,30,15]
list_mrais_16_09 = [1,1,5,30]
list_mrais_17_09 = [1,5,15,30,1,5,15,15]
list_mrais_18_09 = [1,1,15,5,30,1]
list_mrais_19_09 = [5,15,15,1,30,15,1,30]
list_mrais_20_09 = [30,1,30,5]
list_mrais_21_09 = [5,5,5,5,30,1,15,30,1]
list_mrais_22_09 = [15,30,1,15,30,1,15]
list_mrais_23_09 = [30,5,5,1,15,30,5]
list_mrais_24_09 = [1,30,5,15,30,1,1,5]
list_mrais_25_09 = [15,30,1,5,15,30,1]
list_mrais_26_09 = [5,15,30,1,15,5]
list_mrais_27_09 = [30,1,5,15,30]
list_mrais_28_09 = [1,5,15,30,30,1,5,15]
list_mrais_29_09 = [30,1,5,15,30,1]
list_mrais_30_09 = [5,15,30,1,5,15]
list_mrais_01_10 = [30,1,5,15,30,1,5,5,15]
list_mrais_02_10 = [30,1,5,30,1,1,5]
list_mrais_03_10 = [15,30,1,5,15,30]
list_mrais_04_10 = [1,5,15,30,1,5,15,30,1,5,15]
list_mrais_05_10 = [30,1,5,15,30,1,5]
list_mrais_06_10 = [15,30,1,5,15,30]
list_mrais_07_10 = [1,5]
list_mrais_08_10 = [30,15,1]
list_mrais_09_10 = [30,1,15,1,15]
list_mrais_10_10 = [30,15,15,1]
list_mrais_11_10 = [1,30,5,15]
list_mrais_12_10 = [1,30,5,15,30]
list_mrais_13_10 = [1,5,15,30,1]
list_mrais_14_10 = [1,15,30,30]
list_mrais_15_10 = [5,15,1,1,1]
list_mrais_16_10 = [1,1,5,15,30,1]
list_mrais_17_10 = [5,30,15,30,30,30]
list_mrais_18_10 = [1,1,1,30,30,15,30]
list_mrais_19_10 = [5,15,30,15]
list_mrais_20_10 = [1,5,15,30]
list_mrais_21_10 = [1,5,15,30,1]
list_mrais_22_10 = [30,30,1,1,1,30,1,5,15]
list_mrais_23_10 = [30,1,5,15,1,30]
list_mrais_24_10 = [15,5,30]
list_mrais_25_10 = [5,30,1]
list_mrais_26_10 = [1,1,5,15,1,1,30,30,1,30]

list_mrais = list_mrais_10_09 + list_mrais_11_09 + list_mrais_12_09 + list_mrais_13_09 + list_mrais_14_09 + list_mrais_15_09 + list_mrais_16_09 + list_mrais_17_09 + list_mrais_18_09 + list_mrais_19_09 + list_mrais_20_09 + list_mrais_21_09 + list_mrais_22_09 + list_mrais_23_09 + list_mrais_24_09 + list_mrais_25_09 + list_mrais_26_09 + list_mrais_27_09 + list_mrais_28_09 + list_mrais_29_09 + list_mrais_30_09 + list_mrais_01_10 + list_mrais_02_10 + list_mrais_03_10 + list_mrais_04_10 + list_mrais_05_10 + list_mrais_06_10 + list_mrais_07_10 + list_mrais_08_10 + list_mrais_09_10 + list_mrais_10_10 + list_mrais_11_10 + list_mrais_12_10 + list_mrais_13_10 + list_mrais_14_10 + list_mrais_15_10 + list_mrais_16_10 + list_mrais_17_10 + list_mrais_18_10 + list_mrais_19_10 + list_mrais_20_10 + list_mrais_21_10 + list_mrais_22_10 + list_mrais_23_10 + list_mrais_24_10 + list_mrais_25_10 + list_mrais_26_10 
#list_mrais = [5,15,30,1,15,5,1,30,5,5,15,30,30,1,1,5,15,30,1,5,15,30,1,15,5,1,30,30,15,1,5,30,15]
#list_mrais = list_mrais + list_mrais + list_mrais + list_mrais

mrai = 0

#inputFile3 = "features_dataset_10_09_2019_21h20min.txt"

#lis = list(csv.reader(open(inputFile3)))

announcement_file = "features_dataset.csv"
csv_f = open(announcement_file,"w")
columnF = "num_announcements, num_withdrawals, duplicate_announce, longest_aspath, shortest_aspath, avg_as_path, num_prepended_ases, tlong_events, tshort_events, avg_edit_distance, max_edit_distance, num_edited_paths, rare_as1, rare_as2, rare_as3, rare_as4, rare_as5, event_type, mrai\n"
csv_f.write(columnF)
csv_f.close()

inputFileList = ["features_dataset_11_09_2019_01h32min.txt", "features_dataset_11_09_2019_20h18min.txt", "features_dataset_11_09_2019_21h52min.txt", "features_dataset_11_09_2019_23h09min.txt", "features_dataset_12_09_2019_00h57min.txt", "features_dataset_12_09_2019_13h46min.txt", "features_dataset_12_09_2019_15h22min.txt", "features_dataset_12_09_2019_21h41min.txt", "features_dataset_12_09_2019_22h22min.txt", "features_dataset_13_09_2019_00h04min.txt", "features_dataset_13_09_2019_01h17min.txt", "features_dataset_13_09_2019_14h28min.txt", "features_dataset_13_09_2019_15h15min.txt", "features_dataset_13_09_2019_20h28min.txt", "features_dataset_13_09_2019_21h57min.txt", "features_dataset_13_09_2019_23h23min.txt", "features_dataset_14_09_2019_00h35min.txt", "features_dataset_14_09_2019_01h32min.txt", "features_dataset_14_09_2019_05h02min.txt", "features_dataset_14_09_2019_15h56min.txt", "features_dataset_14_09_2019_16h55min.txt", "features_dataset_14_09_2019_18h05min.txt", "features_dataset_14_09_2019_19h28min.txt", "features_dataset_15_09_2019_01h23min.txt", "features_dataset_15_09_2019_02h39min.txt", "features_dataset_15_09_2019_12h31min.txt", "features_dataset_15_09_2019_14h05min.txt", "features_dataset_15_09_2019_15h00min.txt", "features_dataset_15_09_2019_16h11min.txt", "features_dataset_15_09_2019_18h01min.txt", "features_dataset_15_09_2019_20h18min.txt", "features_dataset_15_09_2019_22h53min.txt", "features_dataset_16_09_2019_00h39min.txt", "features_dataset_16_09_2019_03h33min.txt", "features_dataset_16_09_2019_13h34min.txt", "features_dataset_16_09_2019_20h47min.txt","features_dataset_17_09_2019_15h39min.txt", "features_dataset_17_09_2019_19h56min.txt", "features_dataset_17_09_2019_19h14min.txt", "features_dataset_17_09_2019_20h35min.txt", "features_dataset_17_09_2019_21h44min.txt", "features_dataset_17_09_2019_22h31min.txt", "features_dataset_17_09_2019_23h16min.txt", "features_dataset_17_09_2019_23h39min.txt", "features_dataset_18_09_2019_00h30min.txt", "features_dataset_18_09_2019_20h39min.txt", "features_dataset_18_09_2019_21h16min.txt", "features_dataset_18_09_2019_21h45min.txt", "features_dataset_18_09_2019_22h38min.txt", "features_dataset_18_09_2019_23h03min.txt", "features_dataset_19_09_2019_01h39min.txt", "features_dataset_19_09_2019_01h53min.txt", "features_dataset_19_09_2019_14h33min.txt", "features_dataset_19_09_2019_15h10min.txt", "features_dataset_19_09_2019_17h36min.txt", "features_dataset_19_09_2019_19h41min.txt", "features_dataset_19_09_2019_22h46min.txt", "features_dataset_19_09_2019_23h17min.txt", "features_dataset_20_09_2019_00h32min.txt", "features_dataset_20_09_2019_00h50min.txt", "features_dataset_20_09_2019_03h11min.txt", "features_dataset_20_09_2019_19h11min.txt", "features_dataset_21_09_2019_01h26min.txt", "features_dataset_21_09_2019_04h34min.txt", "features_dataset_21_09_2019_12h19min.txt", "features_dataset_21_09_2019_16h09min.txt", "features_dataset_21_09_2019_17h37min.txt", "features_dataset_21_09_2019_18h37min.txt", "features_dataset_21_09_2019_19h25min.txt", "features_dataset_21_09_2019_21h56min.txt", "features_dataset_21_09_2019_23h23min.txt", "features_dataset_22_09_2019_02h15min.txt", "features_dataset_22_09_2019_04h05min.txt", "features_dataset_22_09_2019_16h06min.txt", "features_dataset_22_09_2019_17h41min.txt", "features_dataset_22_09_2019_19h07min.txt", "features_dataset_22_09_2019_20h18min.txt", "features_dataset_22_09_2019_21h53min.txt", "features_dataset_23_09_2019_00h50min.txt", "features_dataset_23_09_2019_02h_18min.txt", "features_dataset_23_09_2019_11h32min.txt", "features_dataset_23_09_2019_13h41min.txt", "features_dataset_23_09_2019_15h18min.txt", "features_dataset_23_09_2019_16h31min.txt", "features_dataset_23_09_2019_20h20min.txt", "features_dataset_24_09_2019_00h02min.txt", "features_dataset_24_09_2019_01h28min.txt", "features_dataset_24_09_2019_02h38min.txt", "features_dataset_24_09_2019_05h03min.txt", "features_dataset_24_09_2019_16h24min.txt", "features_dataset_24_09_2019_18h27min.txt", "features_dataset_24_09_2019_20h31min.txt", "features_dataset_24_09_2019_20h33min.txt", "features_dataset_25_09_2019_11h19min.txt", "features_dataset_25_09_2019_13h57min.txt", "features_dataset_25_09_2019_15h20min.txt", "features_dataset_25_09_2019_17h44min.txt", "features_dataset_25_09_2019_19h07min.txt", "features_dataset_25_09_2019_20h36min.txt", "features_dataset_25_09_2019_23h32min.txt", "features_dataset_26_09_2019_00h35min.txt", "features_dataset_26_09_2019_02h14min.txt", "features_dataset_26_09_2019_15h45min.txt", "features_dataset_26_09_2019_19h49min.txt", "features_dataset_26_09_2019_21h59min.txt", "features_dataset_26_09_2019_22h43min.txt", "features_dataset_27_09_2019_08h06min.txt", "features_dataset_27_09_2019_14h42min.txt", "features_dataset_27_09_2019_15h58min.txt", "features_dataset_27_09_2019_19h49min.txt", "features_dataset_27_09_2019_21h55min.txt", "features_dataset_28_09_2019_00h05min.txt", "features_dataset_28_09_2019_01h48min.txt", "features_dataset_28_09_2019_09h13min.txt", "features_dataset_28_09_2019_12h07min.txt", "features_dataset_28_09_2019_17h13min.txt", "features_dataset_28_09_2019_18h34min.txt", "features_dataset_28_09_2019_19h55min.txt", "features_dataset_28_09_2019_23h30min.txt", "features_dataset_29_09_2019_00h40min.txt", "features_dataset_29_09_2019_02h29min.txt", "features_dataset_29_09_2019_09h25min.txt", "features_dataset_29_09_2019_18h48min.txt", "features_dataset_29_09_2019_20h15min.txt", "features_dataset_29_09_2019_22h14min.txt", "features_dataset_30_09_2019_00h14min.txt", "features_dataset_30_09_2019_01h25min.txt", "features_dataset_30_09_2019_15h15min.txt", "features_dataset_30_09_2019_16h17min.txt", "features_dataset_30_09_2019_20h10min.txt", "features_dataset_30_09_2019_22h59min.txt", "features_dataset_01_10_2019_00h28min.txt", "features_dataset_01_10_2019_02h05min.txt", "features_dataset_01_10_2019_03h33min.txt", "features_dataset_01_10_2019_11h19min.txt", "features_dataset_01_10_2019_13h46min.txt", "features_dataset_01_10_2019_15h31min.txt", "features_dataset_01_10_2019_17h45min.txt", "features_dataset_01_10_2019_19h49min.txt","features_dataset_01_10_2019_21h36min.txt","features_dataset_02_10_2019_00h23min.txt", "features_dataset_02_10_2019_01h45min.txt", "features_dataset_02_10_2019_06h26min.txt", "features_dataset_02_10_2019_14h42min.txt", "features_dataset_02_10_2019_16h17min.txt", "features_dataset_02_10_2019_19h27min.txt", "features_dataset_02_10_2019_20h22min.txt", "features_dataset_03_10_2019_00h54min.txt", "features_dataset_03_10_2019_02h03min.txt", "features_dataset_03_10_2019_13h25min.txt", "features_dataset_03_10_2019_18h48min.txt", "features_dataset_03_10_2019_20h41min.txt", "features_dataset_03_10_2019_23h15min.txt", "features_dataset_04_10_2019_00h27min.txt", "features_dataset_04_10_2019_01h40min.txt", "features_dataset_04_10_2019_03h14min.txt", "features_dataset_04_10_2019_10h47min.txt", "features_dataset_04_10_2019_12h27min.txt", "features_dataset_04_10_2019_13h46min.txt", "features_dataset_04_10_2019_14h51min.txt", "features_dataset_04_10_2019_16h05min.txt", "features_dataset_04_10_2019_20h04min.txt", "features_dataset_04_10_2019_21h10min.txt", "features_dataset_04_10_2019_22h37min.txt", "features_dataset_05_10_2019_01h57min.txt", "features_dataset_05_10_2019_03h23min.txt", "features_dataset_05_10_2019_14h40min.txt", "features_dataset_05_10_2019_15h46min.txt", "features_dataset_05_10_2019_16h58min.txt", "features_dataset_05_10_2019_18h10min.txt", "features_dataset_05_10_2019_19h29min.txt", "features_dataset_06_10_2019_01h57min.txt", "features_dataset_06_10_2019_10h18min.txt", "features_dataset_06_10_2019_13h58min.txt", "features_dataset_06_10_2019_16h38min.txt", "features_dataset_06_10_2019_17h58min.txt", "features_dataset_06_10_2019_20h38min.txt", "features_dataset_07_10_2019_14h46min.txt", "features_dataset_07_10_2019_15h54min.txt", "features_dataset_08_10_2019_03h06min.txt", "features_dataset_08_10_2019_14h45min.txt", "features_dataset_08_10_2019_23h34min.txt", "features_dataset_09_10_2019_01h11min.txt", "features_dataset_09_10_2019_15h47min.txt", "features_dataset_09_10_2019_17h16min.txt", "features_dataset_09_10_2019_19h28min.txt", "features_dataset_09_10_2019_20h50min.txt", "features_dataset_10_10_2019_00h04min.txt", "features_dataset_10_10_2019_02h27min.txt", "features_dataset_10_10_2019_19h45min.txt", "features_dataset_10_10_2019_20h48min.txt", "features_dataset_11_10_2019_16h09min_pc.txt", "features_dataset_11_10_2019_16h09min.txt", "features_dataset_11_10_2019_20h06min.txt", "features_dataset_11_10_2019_22h54min.txt", "features_dataset_12_10_2019_01h10min.txt", "features_dataset_12_10_2019_02h34min.txt", "features_dataset_12_10_2019_13h15min.txt", "features_dataset_12_10_2019_16h02min.txt", "features_dataset_12_10_2019_21h40min.txt", "features_dataset_13_10_2019_00h45min.txt", "features_dataset_13_10_2019_02h40min.txt", "features_dataset_13_10_2019_15h20min.txt", "features_dataset_13_10_2019_17h09min.txt", "features_dataset_13_10_2019_18h54min.txt", "features_dataset_14_10_2019_16h35min.txt", "features_dataset_14_10_2019_16h47min.txt", "features_dataset_14_10_2019_19h43min.txt", "features_dataset_14_10_2019_19h51min.txt", "features_dataset_15_10_2014_01h_13min.txt", "features_dataset_15_10_2019_15h43min.txt", "features_dataset_15_10_2019_19h17min.txt", "features_dataset_15_10_2019_20h09min.txt", "features_dataset_15_10_2019_20h15min.txt", "features_dataset_16_10_2019_00h31min.txt", "features_dataset_16_10_2019_01h47min.txt", "features_dataset_16_10_2019_13h14min.txt", "features_dataset_16_10_2019_15h29min.txt", "features_dataset_16_10_2019_18h57min.txt", "features_dataset_16_10_2019_21h55min.txt", "features_dataset_17_10_2019_01h52min.txt", "features_dataset_17_10_2019_15h53min.txt", "features_dataset_17_10_2019_19h23min.txt", "features_dataset_17_10_2019_19h35min.txt", "features_dataset_17_10_2019_21h40min.txt", "features_dataset_17_10_2019_21h46min.txt", "features_dataset_18_10_2019_01h41min.txt", "features_dataset_18_10_2019_13h57min.txt", "features_dataset_18_10_2019_14h02min.txt", "features_dataset_18_10_2019_21h08min.txt", "features_dataset_18_10_2019_21h14min.txt", "features_dataset_18_10_2019_22h50min.txt", "features_dataset_18_10_2019_22h56min.txt", "features_dataset_19_10_2019_17h05min.txt", "features_dataset_19_10_2019_20h52min.txt", "features_dataset_19_10_2019_22h25min.txt", "features_dataset_19_10_2019_22h33min.txt", "features_dataset_20_10_2019_06h04min.txt", "features_dataset_20_10_2019_13h14min.txt", "features_dataset_20_10_2019_17h37min.txt", "features_dataset_20_10_2019_19h15min.txt", "features_dataset_21_10_2019_02h15min.txt", "features_dataset_21_10_2019_12h27min.txt", "features_dataset_21_10_2019_14h10min.txt", "features_dataset_21_10_2019_22h26min.txt", "features_dataset_21_10_2019_22h30min.txt", "features_dataset_22_10_2019_00h26min.txt", "features_dataset_22_10_2019_00h32min.txt", "features_dataset_22_10_2019_01h44min.txt", "features_dataset_22_10_2019_01h48min.txt", "features_dataset_22_10_2019_14h10min.txt", "features_dataset_22_10_2019_14h17min.txt", "features_dataset_22_10_2019_15h40min.txt", "features_dataset_22_10_2019_19h24min.txt", "features_dataset_22_10_2019_20h54min.txt", "features_dataset_23_10_2019_03h58min.txt", "features_dataset_23_10_2019_04h58min.txt", "features_dataset_23_10_2019_15h11min.txt", "features_dataset_23_10_2019_16h38min.txt", "features_dataset_23_10_2019_20h31min.txt", "features_dataset_23_10_2019_20h36min.txt", "features_dataset_24_10_2019_14h58min.txt", "features_dataset_24_10_2019_21h05min.txt", "features_dataset_24_10_2019_23h02min.txt", "features_dataset_25_10_2019_14h21min.txt", "features_dataset_25_10_2019_15h23min.txt", "features_dataset_25_10_2019_16h30min.txt", "features_dataset_26_10_2019_00h10min.txt", "features_dataset_26_10_2019_00h15min.txt", "features_dataset_26_10_2019_04h48min.txt", "features_dataset_26_10_2019_05h51min.txt", "features_dataset_26_10_2019_19h04_13min.txt", "features_dataset_26_10_2019_19h04min-pc.txt", "features_dataset_26_10_2019_20h28min.txt", "features_dataset_26_10_2019_20h28min_pc.txt", "features_dataset_26_10_2019_21h41min.txt", "features_dataset_26_10_2019_21h41min_pc.txt"]

#input2 = "features_dataset_10_09_2019_21h20min.txt"
#lis = list(csv.reader(open(input2)))
#inputFileList = inputFileList + inputFileList + inputFileList + inputFileList 

for x in range(0,len(inputFileList)):
#for inputFile in inputFileList:
	print inputFileList[x]
	lis = list(csv.reader(open(inputFileList[x])))
	#file_new = open(inputFile, "r")
	#lis = csv.reader(file_new)
	list_announcements = lis[-60:]

	csv_f = open(announcement_file,"a")
						
	for line in list_announcements:
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
				str_line = str_line + "," + str(list_mrais[x]) + "\n"
			if i != 0 and i != len(line)-1: 
				print "i" + str(i)
				print line[i]
				str_line = str_line + str(line[i])
				str_line = str_line + ","
		print "str_line:"
		print str_line
		csv_f.write(str_line)

	csv_f.close()
			

