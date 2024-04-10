import argparse
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import *
import time
import discord_webhook
from discord_webhook import DiscordWebhook
import os

report = "*********************************************" \
         "*********************************************" \
         "general purpose cyber security assessment tool" \
         "Keep in mind false positives may occur, so test" \
         "Cases yourself. Tests SQL, XSS, Wordpress and " \
         "more. \n" # global final response given


def main():

    # collect all the args

    DirectoryEnum = False
    wordlist = ""
    url = "http://127.0.0.1:80"





    if DirectoryEnum:
        if os.path.isfile(wordlist):

            correctURLs = directoryBust(url, wordlist)
        else:
            print("Please select a wordlist, or deselect directory enumeration")


    # call functions
    test_sql()




def test_sql(url):

    # standard list of SQL injections.txt
    global report
    injections = []
    with open('injections.txt') as my_file:
        for line in my_file:
            injections.append(line)


    # 1. Take site and find all form elements. Get urls of these to post to and put in array

    input_name = []

    if url[:6] != "https://":
        url = f'https://{url}'

    r = requests.get(url)
    soup = BeautifulSoup(r.text, "html.parser")

    forms = soup.find_all('form')




    # 2. See if injections.txt provides positive result. Two techniques that can be used
    technique = 0
    for form in forms:
        # First, take two known incorrect injections.txt
        wrongOne = requests.post(url, {form.name:"wrongpass"})
        time.sleep(500)
        wrongTwo = requests.post(url, {form.name:"anotherwrongpass"})


        if wrongOne == wrongTwo: # if these equal, it stands to reason all incorrect responses are
            technique = 1
        else:
            technique = 2 # assume that a technique worked if it takes more than the length between the tests longer
            # may result in false positives or negatives

            greater = max(wrongOne.elapsed.total_seconds(), wrongTwo.elapsed.total_seconds())
            between = abs(wrongOne.elapsed.total_seconds() - wrongTwo.elapsed.total_seconds())

        if technique == 1:

            for injection in injections:
                attempt = requests.post(url, {form.name:injection})
                if attempt.text != wrongOne.text:
                    report = report + "Sql Injection using:  " + injection


        if technique == 2:
            for injection in injections:
                attempt = requests.post(url, {form.name:injection})

                if attempt.elapsed.total_seconds() > greater + (2* between):
                    report = report + "Sql Injection Suspected using:  " + injection



def contactUser(content):

    webhook = DiscordWebhook(url="urltoserverwebhook", content=content)
    response = webhook.execute()

def gui():

    # creates simple gui
    win = tk.Tk()

    Label(win, text="site URL" ).grid(row=0)



def wordpressEnum(url):
    global report
    r = requests.get(url)
    soup = BeautifulSoup.soup(r, "html.parser")

    version = soup.find_all('meta', name="generator")     # finds the generator tag
    if version[0].content.contains("Wordpress"):

        wpSys = requests.get(f'https://www.wpvulnerability.net/core/{version[0].content}/')

        report = report + "Generator tag open. Found vulnerabilities as follows: " + wpSys

def directoryBust(url, wordlist):
    # havnt yet impemented incursive search
    # also threading for speed


    i = 0
    for char in url:          # probably some tricky way to do with string manipulation
        if char == "/":
            break
        else:
            i = i + 1        # code editor hates i++

    baseURL = url[:i]

    correct = []

    with open(wordlist) as wl:
        for line in wl:
            r = requests.get(f'{baseURL}/{line}')
            if r.status_code == 200:
                correct.append(f'{baseURL}/{line}')

            time.sleep(1400) # What is minimum acceptable, may need just a short wordlist
    return correct



# Bust domains
# nmap thing to get flags?
# docs
# miters cvs




