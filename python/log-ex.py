#!/usr/bin/python

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create a file handler

handler = logging.FileHandler('hello.log')
handler.setLevel(logging.INFO)

handler2= logging.StreamHandler()
handler2.setLevel(logging.CRITICAL)

# create a logging format

formatter = logging.Formatter('[%(asctime)s %(levelname)8s]  %(message)s', datefmt='%H:%M')
handler.setFormatter(formatter)
handler2.setFormatter(formatter)


# add the handlers to the logger

logger.addHandler(handler)
logger.addHandler(handler2)

logger.info('Hello baby')
logger.critical('Hello baby')
