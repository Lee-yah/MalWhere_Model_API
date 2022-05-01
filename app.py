# -*- coding: utf-8 -*-
"""
Created on Sat Apr 23 11:54:25 2022

@author: Leah J
"""
#####################
#CREATE API
from flask import Flask,current_app
from flask import jsonify
from flask import request



from Malwhere_Predict import Malwhere_predict

#Create an instance of the class
app = Flask(__name__)

#https://malwhere.herokuapp.com/api/?url=
#@app.route('/<string:URL>/',  methods=['GET', 'POST'])
#URL = "http://127.0.0.1:5000/?url=https://malwhere.herokuapp.com/api/app.exe"

@app.route('/')
def Malwhere_api():
    URL = request.args.get('url')
    prediction= Malwhere_predict(URL)
    return  jsonify({'prediction': prediction})
#WARNING return type must be string, dict, tuple, Response instance, or WSGI callable

# =============================================================================
# if __name__ == '__main__':
#     app.run(debug=True,use_reloader=True,threaded=True)
# 
# =============================================================================
app.run()
