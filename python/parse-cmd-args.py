#!/usr/bin/python

#https://docs.python.org/3/library/argparse.html
import argparse


def main():
    parser = argparse.ArgumentParser(prog='parse.py', description='Test Programm for CMD-ARG parsing')
    parser.add_argument('-t', dest='TARGET', required=True, help='Remote Target') #required
    parser.add_argument('-p', dest='PORT', help='specifiy local port')#optional
    parser.add_argument('--cmd', dest='cmd', action='store_true', help='CMD') #if --cmd -> cmd == True
    parser.add_argument('--def', dest='intVALUE', type=int, default=42, help='default value') #default value int
    parser.add_argument('--verbose', '-v', action='count') #-v =1 -vv =2
    parser.add_argument('--foo', nargs='*')#--foo x y -> foo=['x', 'y']
    parser.add_argument('baz', nargs='*')#args without --something -> ./asd a a -> baz=['a', 'b']
#    parser.add_argument('foo', nargs='+')#min 1 arg
    parser.add_argument('move', choices=['rock', 'paper', 'scissors']) #choices
    parser.add_argument('--fooo', help=argparse.SUPPRESS)#hide from help    
    args = parser.parse_args()
 
    print args.TARGET
    print args
 
#    parser.print_help()

if __name__ == "__main__":
    main()
