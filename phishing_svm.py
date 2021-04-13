# -*- coding: utf-8 -*-

#importing the libraries
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.svm import SVC
import new_phishing1
import pickle
import csv
#import features_extraction
#from sklearn.externals import joblib

#importing the dataset
dataset = pd.read_csv("Training_Dataset.csv")
dataset = dataset.drop('id', 1) #removing unwanted column
x = dataset.iloc[: , :-1].values
x = x[:, [0, 1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17,22, 23, 24, 25, 27, 29]]
y = dataset.iloc[:, -1:].values
y= y.ravel()
print( x.shape,y.shape)
#spliting the dataset into training set and test set
from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.25, random_state =0 )
#splitting order the same
#applying grid search to find best performing parameters 
from sklearn.model_selection import GridSearchCV
parameters = [{'C':[1, 10, 100, 1000], 'gamma': [ 0.1, 0.2,0.3, 0.5]}]
#-1 in n_obs use all processors.
#cv no of folds(groups) in cross validation
# ernel='rbf' : default kernal 
grid_search = GridSearchCV(SVC(kernel='rbf'),  parameters,cv =4, n_jobs= -1)
grid_search.fit(x_train, y_train.ravel())

#printing best parameters 
print("Best Accurancy =" +str( grid_search.best_score_))
print("best parameters =" + str(grid_search.best_params_)) 

#fitting kernel SVM  with best parameters calculated 

classifier = SVC(C=10, kernel = 'rbf', gamma = 0.2 , random_state = 0)
classifier.fit(x_train, y_train.ravel())

#with open('phish_svm.pickle','wb') as f:
#    pickle.dump(classifier, f)
 
#pickle_in = open('phish_svm.pickle','rb')

#classifier = pickle.load(pickle_in)
score_train = classifier.score(x_train, y_train)
print("score", score_train)
print(x_test.shape ,y_test.shape )
score = classifier.score(x_test, y_test)
print("score for test", score)
#predicting the tests set result



