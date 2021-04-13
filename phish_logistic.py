# -*- coding: utf-8 -*-

#importing libraries
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.linear_model import LogisticRegression
#from sklearn.externals import joblib
import new_phishing1
#importing the dataset
dataset = pd.read_csv("Training_Dataset.csv")
dataset = dataset.drop('id', 1) #removing unwanted column
x = dataset.iloc[ : , :-1].values
x = x[:, [0, 1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17,22, 23, 24, 25, 27, 29]]
y = dataset.iloc[:, -1:].values

#spliting the dataset into training set and test set
from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.25, random_state =0 )

#fitting logistic regression 
classifier = LogisticRegression(random_state = 0 ,solver='lbfgs')
classifier.fit(x_train, y_train.ravel())

#predicting the tests set result
print("Accuracy ",classifier.score(x_test, y_test))
y_pred = classifier.predict(x_test)
test_url="https://google.com"
#features_test = features_extraction.main(test_url)
features_test = new_phishing1.main(test_url)
 # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
features_test = np.array(features_test).reshape((1, -1))
pred = classifier.predict(features_test)
#pred =-1 phishing
# pred = 1 legitimate
print(pred)

#confusion matrix
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
print(cm)

