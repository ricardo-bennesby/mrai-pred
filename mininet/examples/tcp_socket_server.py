#import numpy as np # For numerical fast numerical calculations
import pandas as pd # Deals with data
import tensorflow # Imports tensorflow
import keras # Imports keras
import socket
import sys

import numpy as np
#import datetime
#import statistics
from numpy import median
from numpy import mean
from numpy import sum 
from datetime import datetime 
from collections import defaultdict
from collections import OrderedDict
from dateutil.parser import parse
from sklearn.preprocessing import MinMaxScaler

from keras.models import Sequential
from keras.layers import Dense
from keras.layers import LSTM
from keras.models import model_from_json
from keras.models import Model
from keras import backend as K
from keras.backend import tf

from collections import Counter
from keras.preprocessing.sequence import pad_sequences
from keras.layers import Dropout
from pandas import read_csv
import csv
from numpy import array
import time


def predict_mrai():

	seq_length = 60
	num_features = 19

	# create and fit the model
	model = Sequential()
	model.add(LSTM(38, input_shape=(seq_length, num_features)))
	model.add(Dropout(0.1))
	model.add(Dense(6, activation='sigmoid'))
	model.add(Dense(1, activation='relu'))
	model.compile(loss='mae', optimizer='adam')
	# load weights into new model
	model_weights_name = 'trained-weights.h5'
	model.load_weights(model_weights_name)

	#inputFile = "features_dataset_15_09_2019_20h18min.txt"
	#inputFile = "features_dataset_16_09_2019_13h34min.txt"
	inputFile = "/home/ubuntu/ryu/features_dataset.txt"

	list_mrais = [1,5,15,30]

	lis = list(csv.reader(open(inputFile)))
	list_announcements = lis[-60:]

	dataset_y = read_csv('target_dataset.csv')
	values_y = dataset_y.values
	#print("values_y:")
	#print(values_y)
	scalerY = MinMaxScaler(feature_range=(0, 1))
	scaledY = scalerY.fit_transform(values_y)
	#print("scaledY:")
	#print(scaledY)

	#num_samples = len(values_y)/len(list_announcements)
	#print("num_samples:")
	#print(num_samples)


	chosen_mrai = 0
	best_convergence_time = 1000

	for mrai in list_mrais:
		print(".................................")
		print("mrai: "+str(mrai))
		training_x = []		
		cont = 1
		training_features = []
		for line in list_announcements:
			#print(cont)
			#print "line"
			str_line = ""		
			for i in range(0,len(line)):
				if i == 0: 
					line2 = line[i].split('[')
					line3 = line2[1].split(' ')
					#print line3[0]
					str_line = str_line + str(line3[0])
					str_line = str_line + ","
					training_features.append(line3[0])
				if i == len(line)-1:
					line2 = line[i].split(']')
					line3 = line2[0].split(' ')
					#print line3[1]
					str_line = str_line + str(line3[1])
					str_line = str_line + "," + str(mrai) + "\n"
					training_features.append(line3[1])
					training_features.append(mrai)
				if i != 0 and i != len(line)-1: 
					#print("i"+str(i))
					#print(line[i])
					str_line = str_line + str(line[i])
					str_line = str_line + ","
					training_features.append(line[i])
			cont = cont + 1
		training_x.append(training_features)
		
		#print("training_x:")
		#print(training_x)

		scalerX = MinMaxScaler(feature_range=(0, 1))
		scaledX = scalerX.fit_transform(training_x)

		# convert list of lists to array and pad sequences if needed
		#X = pad_sequences(training_x, maxlen=seq_length, dtype='float32')
		#print(X.shape)

		# reshape X to be [samples, time steps, features]
		#scaledX = np.reshape(training_x, (scaledX.shape[0], seq_length, 2))
		X = np.reshape(training_x, (1, seq_length, num_features))
		#X = np.reshape(scaledX, (1, seq_length, num_features))
		#print(X.shape)
		#print("X:")
		#print(X)

		prediction = model.predict(X, verbose=0)
		print("convergence time prediction:")
		print(prediction[0])

		#scaledY = np.reshape(scaledY, (len_values_y,len_y_sequences))

		#mrai_array = array(list_mrais).reshape(-1, 1) 

		#scalerY = MinMaxScaler(feature_range=(0, 1))
		#scaledY = scalerY.fit_transform(mrai_array)

		inv_yhat = scalerY.inverse_transform(prediction)

		#print("inv_yhat:")
		print(int(inv_yhat[0]))
		if int(inv_yhat[0]) < best_convergence_time:
			best_convergence_time = int(inv_yhat[0])
			chosen_mrai = mrai

	print("\n")
	print("*********************")
	print("Chosen MRAI:")
	print(chosen_mrai)
	print("Predicted Convergence Time:")
	print(best_convergence_time) 
	print("*********************")
	return chosen_mrai



# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
print('starting up on port ')
sock.bind(server_address)

#bgpSpeakerIp = '10.208.3.120'
bgpSpeakerIp = '192.168.1.120'
port = 2000

# Listen for incoming connections
sock.listen(1)

enable_msg_sending = 0
predicted_mrai = 0
block_new_announcements = 0
list_announcements = []
static_mrai = 5
while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()

    try:
        print('connected')

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(1024)
            #print("...")
            #print(data)
            if data:
                print('sending data to exabgp router')
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest = (bgpSpeakerIp, port)
                tcp.connect(dest)
                #list_announcements.append(data)
                #if len(list_announcements) > 1:
                #        for announce_msg in list_announcements:
                
                #connection.sendall(announce_msg)
                if enable_msg_sending == 0:
                        if block_new_announcements == 0:
                                predicted_mrai = predict_mrai()
                                #predicted_mrai = static_mrai
                                enable_msg_sending = 1
                                tcp.send(data)
                else:
                        if block_new_announcements == 0:
                                time.sleep(predicted_mrai)
                                print("Sending message after adaptive mrai")
                                tcp.send(data)
                                block_new_announcements = 1
                break
            #else:
                #print >>sys.stderr, 'no more data from', client_address
                #break
            
    finally:
        # Clean up the connection
        #connection.close()
    	print('.........')




