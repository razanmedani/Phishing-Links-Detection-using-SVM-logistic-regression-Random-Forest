# -*- coding: utf-8 -*-
#----------------importing libraries
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import new_phishing1
#from sklearn.externals import joblib


#importing the dataset
dataset = pd.read_csv("Training_Dataset.csv")
dataset = dataset.drop('id', 1) #removing unwanted column

x = dataset.iloc[ : , :-1].values
x = x[:, [0, 1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17,22, 23, 24, 25, 27, 29]]
y = dataset.iloc[:, -1:].values

#spliting the dataset into training set and test set
from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.25, random_state =0 )

#----------------applying grid search to find best performing parameters 
#from sklearn.model_selection import GridSearchCV
#parameters = [{'n_estimators': [100,700],
  #  'max_features': ['sqrt', 'log2','auto'],
 #   'criterion' :['gini', 'entropy']}]

#grid_search = GridSearchCV(RandomForestClassifier(),  param_grid=parameters,cv =5, n_jobs= -1)
#grid_search.fit(x_train, y_train.ravel())
#printing best parameters 
#print("Best Accurancy =" +str( grid_search.best_score_))
#print("best parameters =" + str(grid_search.best_params_)) 
#-------------------------------------------------------------------------

#fitting RandomForest regression with best params 
classifier = RandomForestClassifier(n_estimators = 100, criterion = "gini", max_features = 'log2',  random_state = 0)
history = classifier.fit(x_train, y_train.ravel())
score = classifier.score(x_test, y_test)
print("score",score )

#predicting the tests set result
y_pred = classifier.predict(x_test)

#confusion matrix
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
print(cm)

test_url="https://google.com"
features_test = new_phishing1.main(test_url) #different from random1
 # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
features_test = np.array(features_test).reshape((1, -1))
pred = classifier.predict(features_test)
print(pred[0])

