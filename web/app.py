from flask import Flask, request, render_template
import numpy as np
import pickle
from URLfeature import *

app = Flask(__name__)
app.config["DEBUG"] = True
model = pickle.load(open("../XGBoost.pickle.dat", "rb")) #load the model

def featureExtraction(test_url):
    feature_result = []
    test_domain = getDomain(test_url)

    feature_result.append(havingIP(test_url))
    feature_result.append(haveAtSign(test_url))
    feature_result.append(getLength(test_url))
    feature_result.append(getDepth(test_url))
    feature_result.append(redirection(test_url))
    feature_result.append(httpDomain(test_url))
    feature_result.append(tinyURL(test_url))
    feature_result.append(prefixSuffix(test_url))
    feature_result.append(dns(test_url))
    feature_result.append(web_traffic(test_url))
    feature_result.append(1 if dns == 1 else domainAge(test_domain))
    feature_result.append(1 if dns == 1 else domainEnd(test_domain))
    feature_result.append(iframe(test_url))
    feature_result.append(mouseOver(test_url))
    feature_result.append(rightClick(test_url))
    feature_result.append(forwarding(test_url))

    return feature_result

def decetion(url):
    computed = featureExtraction(url)
    return np.array([computed])

@app.route('/', methods=['GET', 'POST'])
def home():
    url = request.form.get("url") #get url from request url

    if request.method == "POST": # If a form is submitted
        if len(url) == 0:
          prediction = ""
          res = ""
          return render_template("index.html", output = prediction, results = res, url = "")

        if not (url.startswith('http://') or url.startswith('https://')): #if given url does not start with http or https add http
            url = 'http://' + url
        print("url:", url)

        decetion_result = decetion(url) #get feature vector
        prediction = model.predict(decetion_result)[0] #predict the url

        if prediction == 1:
            prediction_result = "UNSAFE"
        else:
            prediction_result = "SAFE"

        prediction = prediction_result
        res = decetion_result[0]
        return render_template("index.html", output = prediction, results = res, url = url) #render the template with the prediction

    else:
        prediction = ""
        res = ""
        return render_template("index.html", output = prediction, results = res, url = "") 
        
app.run()