#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Anonymize IP and Username from a CSV log
# @author: susmit.shannigrahi@colostate.edu
#
#    This is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

import argparse
import logging
import random


def anonymize(passed_input_file, passed_output_file, delim, log):
    """Input = Tab seperated file, Output = Tab seperated file with IP and
    Username anonymized"""
    log.info("Starting anonymization")

    encountered_ip_address = {}

    with open(passed_input_file, 'r') as read_f, open(passed_output_file, 'w') as write_f:
        for line in read_f:
            #get the parameters from this line
            columns = line.split(delim)
            index = columns[0]
            username = columns[1]
            ip = columns[5]
            hash_u = columns[12]

            # replace username by HASH from user_id_hash
            columns[1] = hash_u
            log.debug("Old Username: {}, New Username {}"\
                      .format(username, hash_u))

            # replace last 8 bits of IP with random number, column[5]
            
            #if we have already seen this IP address, replace this from the list
            if ip in encountered_ip_address:
                columns[5] = encountered_ip_address[ip]
                
            #else, anonimyze the ip and record it in the list
            else:
                try:
                    split_ip = ip.split('.')
                    split_ip[3] = str(random.randint(1, 254))
                    joined_ip = '.'.join(split_ip)
                    columns[5] = joined_ip
                    encountered_ip_address[ip] = joined_ip
                except IndexError:
                    log.warning("Malformed IP address on line {}, skipping. "\
                                .format(index))
                    continue

            log.debug("Old IP: {}, New IP {}".format(ip, columns[5]))

            # create new line and write to output file
            new_line = delim.join(columns)
            write_f.write(new_line)


if __name__ == '__main__':

    #parse the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input_file',
                        help='input file in tab seperated format'
                        , required=True)
    parser.add_argument('-o', '--output_file', help='output file'
                        , required=True)
    parser.add_argument('-d', '--delimiter', help='output file'
                        , default='\t')
    parser.add_argument('-l', '--log', help='log level'
                        , default='INFO')

    args = parser.parse_args()
    input_file = args.input_file
    output_file = args.output_file
    delimiter = args.delimiter
    loglevel = args.log

    #set up logging
    numeric_level = getattr(logging, loglevel.upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid Log Level: {}. Valid options are\
                        INFO, WARNING, DEBUG, ERROR, CRITICAL'.format(loglevel))

    logging.basicConfig(level=numeric_level)
    logger = logging.getLogger(__name__)
    logging.info('Anonymizing input file: {}'.format(input_file))
    logging.info('Writing output to: {}'.format(output_file))
    logging.info('Delimiter is: {}'.format(delimiter))


    #anonymize
    anonymize(input_file, output_file, delimiter, logger)
    logging.info("Anonymization complete")
