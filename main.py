#!/usr/bin/env python3
import os

# Il tuo banner in ASCII Art
BANNER = r"""
________  _______   ___  ________  ___  ________      
|\   __  \|\  ___ \ |\  \|\   ____\|\  \|\   ____\     
\ \  \|\  \ \   __/|\ \  \ \  \___|\ \  \ \  \___|_    
 \ \   __  \ \  \_|/_\ \  \ \  \  __\ \  \ \_____  \   
  \ \  \ \  \ \  \_|\ \ \  \ \  \|\  \ \  \|____|\  \  
   \ \__\ \__\ \_______\ \__\ \_______\ \__\____\_\  \ 
    \|__|\|__|\|_______|\|__|\|_______|\|__|\_________\
                                           \|_________|
                                                       
                                                       
"""

def pulisci_schermo():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    pulisci_schermo()
    
    #Stampa del banner 
    print(BANNER)
    print("=" * 60)
    print("  [+] Tool active: ")
    print("=" * 60)
    print()
    
    # inizio logica del programma
    input("Press enter to start...")

if __name__ == "__main__":
    main()