# Command to run in terminal before running client
## Set environment variable for flask
    export FLASK_APP=app.py

## To initialise database with SQLalchemy :
    db migrate -m "Creating DB"
    db upgrade

## To run the servor :
    flask run