from pandas import DataFrame
from pandas import Series
from math import sqrt
from numpy import concatenate
from pandas import read_csv
from pandas import DataFrame
from pandas import concat
from sklearn.preprocessing import MinMaxScaler
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import mean_squared_error
#import numpy
import pandas as pd
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

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import LSTM
from tensorflow.keras.models import model_from_json
#import numpy
import pandas as pd
from keras import backend as K
from keras.backend import tf

from collections import Counter
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.layers import Dropout
import csv

num_timestamps = 60
test_num_days = 1
seq_length = 60
num_features = 19
num_epochs = 100
list_models = []

y_timestamps = []

dataset = read_csv('features_dataset.csv')
	
values = dataset.values
print("values:")
print(values)

#num_timestamps = (len(values))/(num_events)
num_events = (len(values))/num_timestamps
print("num_timestamps:")
print(num_timestamps)

dataset_y = read_csv('target_dataset.csv')
values_y = dataset_y.values

print("values_y:")
print(values_y)

training_list = []
for num_event in range(0,num_events):
	start_index = int(num_event * num_timestamps)
	print("start_index: "+str(start_index))
	print(" ---- Event " + str(num_events) + "----- ")
	print(values[int(start_index):int(start_index)+int(num_timestamps),])
	training_list.append(values[int(start_index):int(start_index)+int(num_timestamps)])

print("len training_list:")
print(len(training_list))
print(training_list)


#values_y = np.array(training_y_lists).reshape(-1,1) # transform valuesY to array
scalerY = MinMaxScaler(feature_range=(0, 1))
scaledY = scalerY.fit_transform(values_y)

#values_y = pad_sequences(values_y, maxlen=1, dtype='float32')
len_y_sequences = 1
len_values_y = int(len(values_y)/len_y_sequences)
scaledY = np.reshape(scaledY, (len_values_y,len_y_sequences))
#scaledY = np.reshape(scaledY, (len(values_y)/6,6))
print(scaledY.shape)
#scaledY = np.reshape(scaledY,(6,6))

print(values_y)
print(scaledY)

print("scaledY.shape: "+str(scaledY.shape))

training_x = []
for x in range(0,num_events):
	training_features = []
	for training_list_len in range(0,len(training_list[x])):
		training_features.append(training_list[x][training_list_len][0])
		training_features.append(training_list[x][training_list_len][1])
		training_features.append(training_list[x][training_list_len][2])
		training_features.append(training_list[x][training_list_len][3])
		training_features.append(training_list[x][training_list_len][4])
		training_features.append(training_list[x][training_list_len][5])
		training_features.append(training_list[x][training_list_len][6])
		training_features.append(training_list[x][training_list_len][7])
		training_features.append(training_list[x][training_list_len][8])
		training_features.append(training_list[x][training_list_len][9])
		training_features.append(training_list[x][training_list_len][10])
		training_features.append(training_list[x][training_list_len][11])
		training_features.append(training_list[x][training_list_len][12])
		training_features.append(training_list[x][training_list_len][13])
		training_features.append(training_list[x][training_list_len][14])
		training_features.append(training_list[x][training_list_len][15])
		training_features.append(training_list[x][training_list_len][16])
		training_features.append(training_list[x][training_list_len][17])
		training_features.append(training_list[x][training_list_len][18])
	training_x.append(training_features)
		
print(training_x)

scalerX = MinMaxScaler(feature_range=(0, 1))
scaledX = scalerX.fit_transform(training_x)

# convert list of lists to array and pad sequences if needed
X = pad_sequences(training_x, maxlen=seq_length, dtype='float32')
print(X.shape)

# reshape X to be [samples, time steps, features]
#scaledX = np.reshape(training_x, (scaledX.shape[0], seq_length, 2))
X = np.reshape(training_x, (X.shape[0], seq_length, num_features))
#X = np.reshape(scaledX, (X.shape[0], seq_length, num_features))
print(X.shape)

# create and fit the model
model = Sequential()
model.add(LSTM(38, input_shape=(X.shape[1], X.shape[2])))
model.add(Dropout(0.2))
model.add(Dense(6, activation='sigmoid'))
#model.add(Dense(12, activation='relu'))
#model.add(Dense(scaledY.shape[1], activation='sigmoid'))
model.add(Dense(scaledY.shape[1], activation='relu'))
model.compile(loss='mae', optimizer='adam')
#model.compile(loss='binary_crossentropy', optimizer='adam')
model.fit(X, scaledY, epochs=num_epochs, batch_size=int(len(training_x)/4), validation_data=(X, scaledY), verbose=2, shuffle=False)
#model.fit(X, scaledY, epochs=num_epochs, batch_size=1, validation_data=(X, scaledY), verbose=2, shuffle=False)

prediction = model.predict(X, verbose=0)
inv_yhat = scalerY.inverse_transform(prediction)
#inv_yhat = inv_yhat[:,0]

print("inv_yhat:")
print(inv_yhat)

inv_y = scalerY.inverse_transform(scaledY)
#inv_y = inv_y[:,0]

print("inv_y:")
print(inv_y)

#print("\n")
#print "|  Predicted        -------       Real       "
pred_len = len(prediction)
print("pred_len: "+str(pred_len))

iterator = 0
while iterator < pred_len:
	#print("|   %.2f        -------        %.2f     " % (inv_yhat[iterator],inv_y[iterator]) )
	#print(inv_yhat[iterator].tolist(),inv_y[iterator].tolist())
	print("|  PREDICTED       -------       TARGET")
	for predict_item in range(0,len(inv_yhat[iterator].tolist())):
		print("|   %.2f        -------        %.2f     " % (inv_yhat[iterator].tolist()[predict_item],inv_y[iterator].tolist()[predict_item]) )	
	#print("|   %.2f        -------        %.2f     " % (inv_yhat[iterator],inv_y[iterator]) )
	iterator += 1

# serialize model to JSON
print("Saving trained model...")
model_json = model.to_json()
model_file_name = "trained-model.json"
with open(model_file_name, "w") as json_file:
    	json_file.write(model_json)
# serialize weights to HDF5
print("Saving model weights...")
model_weights_name = 'trained-weights.h5'
model.save_weights(model_weights_name)



inputFile = "features_dataset_15_09_2019_20h18min.txt"
#inputFile = "features_dataset_16_09_2019_13h34min.txt"

list_mrais = [0,5,15,30]

lis = list(csv.reader(open(inputFile)))
list_announcements = lis[-60:]

dataset_y = read_csv('target_dataset.csv')
values_y = dataset_y.values
print("values_y:")
print(values_y)
scalerY = MinMaxScaler(feature_range=(0, 1))
scaledY = scalerY.fit_transform(values_y)
print("scaledY:")
print(scaledY)

#num_samples = len(values_y)/len(list_announcements)
#print("num_samples:")
#print(num_samples)

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
		
	print("training_x:")
	print(training_x)

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

	tfX = tf.convert_to_tensor(X,dtype=tf.float32)
	prediction = model.predict(tfX, verbose=0)
	print("convergence time prediction:")
	print(prediction[0])

	#scaledY = np.reshape(scaledY, (len_values_y,len_y_sequences))

	#mrai_array = array(list_mrais).reshape(-1, 1) 

	#scalerY = MinMaxScaler(feature_range=(0, 1))
	#scaledY = scalerY.fit_transform(mrai_array)

	inv_yhat = scalerY.inverse_transform(prediction)

	#print("inv_yhat:")
	print(int(inv_yhat[0]))


inputFile = "features_dataset_16_09_2019_13h34min.txt"
#inputFile = "features_dataset_16_09_2019_13h34min.txt"

list_mrais = [0,5,15,30]

lis = list(csv.reader(open(inputFile)))
list_announcements = lis[-60:]

dataset_y = read_csv('target_dataset.csv')
values_y = dataset_y.values
print("values_y:")
print(values_y)
scalerY = MinMaxScaler(feature_range=(0, 1))
scaledY = scalerY.fit_transform(values_y)
print("scaledY:")
print(scaledY)

#num_samples = len(values_y)/len(list_announcements)
#print("num_samples:")
#print(num_samples)

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
		
	print("training_x:")
	print(training_x)

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

	tfX = tf.convert_to_tensor(X,dtype=tf.float32)
	prediction = model.predict(tfX, verbose=0)
	print("convergence time prediction:")
	print(prediction[0])

	#scaledY = np.reshape(scaledY, (len_values_y,len_y_sequences))

	#mrai_array = array(list_mrais).reshape(-1, 1) 

	#scalerY = MinMaxScaler(feature_range=(0, 1))
	#scaledY = scalerY.fit_transform(mrai_array)

	inv_yhat = scalerY.inverse_transform(prediction)

	#print("inv_yhat:")
	print(int(inv_yhat[0]))


inputFile = "features_dataset_14_09_2019_00h35min.txt"
#inputFile = "features_dataset_16_09_2019_13h34min.txt"

list_mrais = [0,5,15,30]

lis = list(csv.reader(open(inputFile)))
list_announcements = lis[-60:]

dataset_y = read_csv('target_dataset.csv')
values_y = dataset_y.values
print("values_y:")
print(values_y)
scalerY = MinMaxScaler(feature_range=(0, 1))
scaledY = scalerY.fit_transform(values_y)
print("scaledY:")
print(scaledY)

#num_samples = len(values_y)/len(list_announcements)
#print("num_samples:")
#print(num_samples)

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
		
	print("training_x:")
	print(training_x)

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

	tfX = tf.convert_to_tensor(X,dtype=tf.float32)
	prediction = model.predict(tfX, verbose=0)
	print("convergence time prediction:")
	print(prediction[0])

	#scaledY = np.reshape(scaledY, (len_values_y,len_y_sequences))

	#mrai_array = array(list_mrais).reshape(-1, 1) 

	#scalerY = MinMaxScaler(feature_range=(0, 1))
	#scaledY = scalerY.fit_transform(mrai_array)

	inv_yhat = scalerY.inverse_transform(prediction)

	#print("inv_yhat:")
	print(int(inv_yhat[0]))



inputFile = "features_dataset_12_09_2019_00h57min.txt"
#inputFile = "features_dataset_16_09_2019_13h34min.txt"

list_mrais = [0,5,15,30]

lis = list(csv.reader(open(inputFile)))
list_announcements = lis[-60:]

dataset_y = read_csv('target_dataset.csv')
values_y = dataset_y.values
print("values_y:")
print(values_y)
scalerY = MinMaxScaler(feature_range=(0, 1))
scaledY = scalerY.fit_transform(values_y)
print("scaledY:")
print(scaledY)

#num_samples = len(values_y)/len(list_announcements)
#print("num_samples:")
#print(num_samples)

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
		
	print("training_x:")
	print(training_x)

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

	tfX = tf.convert_to_tensor(X,dtype=tf.float32)
	prediction = model.predict(tfX, verbose=0)
	print("convergence time prediction:")
	print(prediction[0])

	#scaledY = np.reshape(scaledY, (len_values_y,len_y_sequences))

	#mrai_array = array(list_mrais).reshape(-1, 1) 

	#scalerY = MinMaxScaler(feature_range=(0, 1))
	#scaledY = scalerY.fit_transform(mrai_array)

	inv_yhat = scalerY.inverse_transform(prediction)

	#print("inv_yhat:")
	print(int(inv_yhat[0]))



