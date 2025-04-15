#!/usr/bin/env python3
import argparse
import sys
import os

#THESE ARE THE FILE IMPORTS, BE SURE TO UPDATE IF MORE GET ADDED OR IF I MISSED ONE
import Data_Struct
import init
import checkout
import checkin
import remove
import show_cases
import show_history
import verify
import Summary
import show_items

#This is a test, to make sure I'm actually interacitng with the other files
print(f"You know what is an overused number? {Data_Struct.funny_number()}")


#REMINDER: IT HAS TO EXIT WITH NON-ZERO IF IT CRASHES/BREAKS IN A WEIRD WAY
#Importing necessary modules

#Placeholder Command Handler Functions 
#These will be filled in or replaced later, we just need a bare skeleton now.

def handle_init(args):
    print(f"Executing: init")
    #Bare minimum: Check if BCHOC_FILE_PATH is set
    if not os.environ.get('BCHOC_FILE_PATH'):
         print("Warning: BCHOC_FILE_PATH environment variable not set.", file=sys.stderr)
         #Don't exit yet in boilerplate, just warn
    #TODO: Implement init logic

def handle_add(args):
    print(f"Executing: add (Case: {args.c}, Items: {args.i}, Creator: {args.g})")
    #TODO: Implement add logic

def handle_checkout(args):
    print(f"Executing: checkout (Item: {args.i})")
    #TODO: Implement checkout logic

def handle_checkin(args):
    print(f"Executing: checkin (Item: {args.i})")
    #TODO: Implement checkin logic

def handle_show_cases(args):
    print(f"Executing: show cases")
    #TODO: Implement show cases logic

def handle_show_items(args):
    print(f"Executing: show items (Case: {args.c})")
    #TODO: Implement show items logic

def handle_show_history(args):
    print(f"Executing: show history (Case: {args.c}, Item: {args.i}, Num: {args.n}, Reverse: {args.reverse})")
    #TODO: Implement show history logic

def handle_remove(args):
    print(f"Executing: remove (Item: {args.i}, Reason: {args.y}, Owner: {args.o})")
    #TODO: Implement remove logic

def handle_verify(args):
    print(f"Executing: verify")
    #TODO: Implement verify logic

def handle_summary(args):
    print(f"Executing: summary (Case: {args.c})")
    #TODO: Implement summary logic

#Main starts here -----------------------------------------------------------------------

def main():
    #parser
    parser = argparse.ArgumentParser(
        description="Blockchain Chain of Custody Tool (INCOMPLETE, PRE-PRE-PRE ALPHA LEAK THIS TO LAUGH AT PEOPLE)",
        prog="bchoc" #Set the program name for help messages
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    #init 
    parser_init = subparsers.add_parser('init', help='Initialize the blockchain')
    parser_init.set_defaults(func=handle_init)

    #add 
    parser_add = subparsers.add_parser('add', help='Add a new evidence item')
    parser_add.add_argument('-c', type=str, required=True, help='Case ID (UUID format)')
    parser_add.add_argument('-i', type=str, required=True, nargs='+', help='Item ID(s)')
    parser_add.add_argument('-g', type=str, required=True, help='Creator name')
    parser_add.add_argument('-p', type=str, required=True, help="Password")
    parser_add.set_defaults(func=handle_add)

    #checkout 
    parser_checkout = subparsers.add_parser('checkout', help='Check out an evidence item')
    parser_checkout.add_argument('-i', type=str, required=True, help='Item ID')
    parser_checkout.add_argument('-p', type=str, required=True, help="Password")
    parser_checkout.set_defaults(func=handle_checkout)

    #checkin 
    parser_checkin = subparsers.add_parser('checkin', help='Check in an evidence item')
    parser_checkin.add_argument('-i', type=str, required=True, help='Item ID')
    parser_checkin.add_argument('-p', type=str, required=True, help="Password")
    parser_checkin.set_defaults(func=handle_checkin)

    #show (show subcommands) 
    parser_show_parent = subparsers.add_parser('show', help='Show information from the blockchain')
    show_subparsers = parser_show_parent.add_subparsers(dest='show_command', help='What to show', required=True)

    #show cases 
    parser_cases = show_subparsers.add_parser('cases', help='Display all case IDs')
    parser_cases.add_argument('-p', type=str, required=True, help="Password")
    parser_cases.set_defaults(func=handle_show_cases)

    #show items 
    parser_items = show_subparsers.add_parser('items', help='Display item IDs for a case')
    parser_items.add_argument('-c', type=str, required=True, help='Case ID (UUID format)')
    parser_items.add_argument('-p', type=str, required=True, help="Password")
    parser_items.set_defaults(func=handle_show_items)

    #show history 
    parser_history = show_subparsers.add_parser('history', help='Display history entries')
    parser_history.add_argument('-c', type=str, help='Filter by Case ID')
    parser_history.add_argument('-i', type=str, help='Filter by Item ID')
    parser_history.add_argument('-n', type=int, help='Show only N entries')
    parser_history.add_argument('-r', '--reverse', action='store_true', help='Show newest first')
    parser_history.add_argument('-p', type=str, required=True, help="Password")
    parser_history.set_defaults(func=handle_show_history)

    #remove 
    parser_remove = subparsers.add_parser('remove', help='Remove an item')
    parser_remove.add_argument('-i', type=str, required=True, help='Item ID')
    #Using choices based on spec page 5
    parser_remove.add_argument('-y', '--why', type=str, required=True,
                               choices=['DISPOSED', 'DESTROYED', 'RELEASED'],
                               help='Reason for removal')
    parser_remove.add_argument('-o', '--owner', type=str, help='Lawful owner (if reason is RELEASED)')
    parser_remove.add_argument('-p', type=str, required=True, help="Password (creator's)")
    parser_remove.set_defaults(func=handle_remove)

    #verify 
    parser_verify = subparsers.add_parser('verify', help='Verify blockchain integrity')
    parser_verify.set_defaults(func=handle_verify)

    #summary 
    parser_summary = subparsers.add_parser('summary', help='Show item state summary for a case')
    parser_summary.add_argument('-c', type=str, required=True, help='Case ID (UUID format)')
    #Password not listed for summary in the command list (pg 3), add if required by instructor/TA clarification
    #parser_summary.add_argument('-p', type=str, required=True, help="Password (owner's)")
    parser_summary.set_defaults(func=handle_summary)

    #Parse arguments from sys.argv
    args = parser.parse_args()

    #Call the appropriate handler function based on the command
    #The handler function is stored in args.func by set_defaults
    if hasattr(args, 'func'):
        try:
            args.func(args)
            #You might want successful commands to exit 0 implicitly
            #sys.exit(0) #Optional: explicit success exit
        except Exception as e:
            #Basic error handling for unexpected issues in handlers
            print(f"An error occurred: {e}", file=sys.stderr)
            sys.exit(1) #Exit with non-zero status for errors
    else:
        #It'd be really funny if I left this as 0. But I shouldn't. Because we'd lose points. smh.
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
    