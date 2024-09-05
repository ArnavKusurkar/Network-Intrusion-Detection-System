import logging

logging.basicConfig(filename='nids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def log_alert(alert):
    logging.info(alert)

