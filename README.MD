# Command to run in terminal before running client
## Creating Python env :
    conda create -n env_flask_chat python=3.7 -f requirements.txt
    source activate env_flask_chat

## Set environment variable for flask
    export FLASK_APP=app.py

## To initialise database with SQLalchemy :
    db migrate -m "Creating DB"
    db upgrade

## To run the servor :
    flask run