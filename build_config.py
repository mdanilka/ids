import configparser
config = configparser.ConfigParser()
config['GLOBAL'] = {'NetworkInterface': 'iface_input_here',
                    'Timeout': 0}
with open('config.txt', 'w') as configfile:
    config.write(configfile)
