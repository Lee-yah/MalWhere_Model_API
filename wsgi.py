# -*- coding: utf-8 -*-
"""
Created on Sun May  1 16:50:10 2022

@author: Leah J.
"""

#Flask does not have a WSGI HTTP Server, so
#we will use the most common library Gunicorn. For this, we will create a new wsgi.py file.\

from app import app

if __name__ == "__main__":
    app.run()