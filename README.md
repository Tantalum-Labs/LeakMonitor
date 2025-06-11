== Install ==
virtualenv venv
source ./venv/bin/activate
pip install -r requirements.txt
Grab a config.json from 1password and place into same path

== Use ==
source ./venv/bin/activate
python leakMonitor.py textFileOfDomains.txt "Customer Name" [silent|notify]
