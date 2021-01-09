SETTINGS = {
    # #########################################################################
    #
    # DATABASE_URL
    # ------------
    # This setting contains the information neccessary to connect to the MySQL
    # server for this webapp2 application.
    #   Uses the following format:
    #               'mysql://[username]:[password]@[server]/[database]',
    # where username and password are the credentials for a MySQL user and
    # database and server identify the database you want the webapp2 data to be
    # stored in.
    #
    'DATABASE_URL': 'mysql+pymysql://sec:sec.local.db@localhost/sec_webapp2',
    #
    # #########################################################################
    #
    # SERVER_URL
    # ----------
    # This setting contains the URL under which the webapp2 application will be
    # p u b l i c l y  available under, without any "https://" in front of it.
    #
    'SERVER_URL': 'localhost:5000',
    #
    # #########################################################################
    #
    # SESSION_SECRET_KEY
    # ------------------
    # This setting contains the secret key, which Flask will use to provide
    # user sessions (signing in). Change this to a random value and do not give
    # it to other people or they will be able to forge user sessions.
    #
    'SESSION_SECRET_KEY': 'sec.webapp2.key',
    #
    # #########################################################################
}
