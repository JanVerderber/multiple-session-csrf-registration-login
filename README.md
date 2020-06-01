# Multiple session and CSRF tokens registration and login app

A moderately simple registration and login with multiple sessions and CSRF tokens per user. 

## How is this app built?
This app is built with Python using Flask. 

## Which database system does it use?
It uses SQL database - SQLite. The database is located in the root of the app. It's called app_database.db. You can view this database with SQLite shell but I recommend using SQLite Studio, which gives you a nice
interface and is easier to work with.

## How to start the app?
Starting the app is pretty simple. You only need Python 3. The best way is to run the app is by using the app.py in the root of the app. If you are using PyCharm you can right click on the app.py file and select "Run".
When you first open the app in PyCharm it will notify you that you have to install all the packages from requirements.txt. Accept this message and wait for the install to complete. If you are not using PyCharm you will have
to manually install these packages using this command: pip install -r requirements.txt
If you are not using PyCharm to start the app, use this command: python app.py

## What does this app offer?
- Users can register with username and password (No e-mail)
- Users can login with username and password
- When users login, they see all the users registered and their ID
- Users can change their password using /change-password
- Multiple sessions so users can have more sessions (Login from different clients)
- CSRF protection


