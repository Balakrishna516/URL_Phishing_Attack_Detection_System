from flask import Flask, request, render_template
import pickle
import numpy as np
import joblib

app = Flask(__name__)  # ✅ Initialize the Flask app

# ✅ Load the Phishing Model
try:
    with open('Phishing_model.pkl', 'rb') as file:
        model = joblib.load(file)  # Use joblib or pickle based on how it was saved
except Exception as e:
    print(f"Error loading model: {e}")
    model = None  # Prevent crashes if the model is unavailable

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/inspect")
def inspect():
    return render_template("inspect.html")

@app.route("/output", methods=["GET", "POST"])
def output():
    if request.method == 'POST':
        try:
            # ✅ Convert input to integers (or floats if necessary)
            var1 = int(request.form["UsingIP"])
            var2 = int(request.form["PrefixSuffix-"])
            var3 = int(request.form["SubDomains"])
            var4 = int(request.form["HTTPS"])
            var5 = int(request.form["NonStdPort"])
            var6 = int(request.form["HTTPSDomainURL"])
            var7 = int(request.form["RequestURL"])
            var8 = int(request.form["AnchorURL"])
            var9 = int(request.form["LinksInScriptTags"])
            var10 = int(request.form["ServerFormHandler"])
            var11 = int(request.form["InfoEmail"])
            var12 = int(request.form["AbnormalURL"])
            var13 = int(request.form["WebsiteForwarding"])
            var14 = int(request.form["StatusBarCust"])
            var15 = int(request.form["DisableRightClick"])
            var16 = int(request.form["AgeofDomain"])
            var17 = int(request.form["DNSRecording"])
            var18 = int(request.form["WebsiteTraffic"])
            var19 = int(request.form["PageRank"])
            var20 = int(request.form["GoogleIndex"])
            var21 = int(request.form["StatsReport"])

            # ✅ Convert to NumPy array
            predict_data = np.array([var1, var2, var3, var4, var5, var6, var7, var8, var9, var10,
                                     var11, var12, var13, var14, var15, var16, var17, var18, var19, var20, var21]).reshape(1, -1)

            # ✅ Check if the model is loaded properly
            if model is None:
                return render_template('output.html', predict="Model not loaded properly.")

            # ✅ Make a prediction
            prediction = model.predict(predict_data)

            # ✅ Interpret the prediction
            if prediction == 1:
                result = "Safe"
            elif prediction == -1:
                result = "Not Safe"
            else:
                result = "Suspicious"

            return render_template('output.html', predict=result)

        except Exception as e:
            return render_template('output.html', predict=f"Error: {e}")

    return render_template("output.html")

if __name__ == "__main__":
    app.run(debug=False)
