import configparser
config = configparser.ConfigParser()
config['GLOBAL'] = {'NetworkInterface': 'wlx1cbfce753f08',
                    'Timeout': 0}
with open('config.txt', 'w') as configfile:
    config.write(configfile)