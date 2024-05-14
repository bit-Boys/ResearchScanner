# NOTE: This is part of an internship project. This software has a wide degree of funcitonality, please use responsibly, and always with permissions from sites that are tested against.


import argparse
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import *
import time
import discord_webhook
from discord_webhook import DiscordWebhook
import os
import nmap3
import socket
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import threading

report = "*********************************************" \
         "*********************************************" \
         "general purpose cyber security assessment tool" \
         "Keep in mind false positives may occur, so test" \
         "Cases yourself. Tests SQL, XSS, Wordpress and " \
         "more. \n"  # global final response given

class guiAction(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, default=argparse.SUPPRESS, **kwargs) # allow for positional url or gui

    def __call__(self, parser, namespace, values, option_string, **kwargs):
        win = tk.Tk()

        win.title("General Vulnerability Scanner")
        win.geometry('400x400')
        win.configure(background="blue")


        urlLabel = Label(win, text="Enter URL: ").grid(row=0, column=0, pady=4, padx=1)
        urlBox = Entry(win)
        urlBox.grid(row=0, column=1, pady=4, padx=1)

        wordlistLabel = Label(win, text="Path to wordlist here: ").grid(row=1, column=1, pady=4, padx=1)
        wordlistBox = Entry(win)
        wordlistBox.grid(row=1, column=2, pady=4, padx=1)

        doDirect = tk.BooleanVar()
        doAll = tk.BooleanVar()
        doSQL = tk.BooleanVar()
        doXSS = tk.BooleanVar()
        doWordpress = tk.BooleanVar()

        tk.Checkbutton(win, text='Directory Enumeration', variable=doDirect, onvalue=True, offvalue=False,).grid(row=1, column=0, pady=4, padx=1)
        tk.Checkbutton(win, text='Every Feature', variable=doAll, onvalue=True, offvalue=False, ).grid(row=2, column=0, pady=4, padx=1)
        tk.Checkbutton(win, text='SQL Injection', variable=doSQL, onvalue=True, offvalue=False, ).grid(row=2, column=1, pady=4, padx=1)
        tk.Checkbutton(win, text='XSS', variable=doXSS, onvalue=True, offvalue=False, ).grid(row=2, column=2, pady=4, padx=1)
        tk.Checkbutton(win, text='Wordpress', variable=doWordpress, onvalue=True, offvalue=False, ).grid(row=3, column=0, pady=4, padx=1)

        submit = tk.Button(win, text="Submit", command=lambda: self.onSubmit(urlBox, wordlistBox, doDirect, doAll, doSQL, doXSS)).grid(row=4, column=1, pady=3)


        win.mainloop()

        parser.exit()

    def onSubmit(self, urlBox, wordlistBox, doDirect, doAll, doSQL, doXSS): # Run everything selected, when submitted


        url = urlBox.get()
        correctURLs = [url]


        DirectoryEnum = ""

        if doDirect.get() or doAll.get():
            DirectoryEnum = True

            wordlist = wordlistBox.get()



        if DirectoryEnum:
            if os.path.isfile(wordlist):

                correctURLs = directoryBust(url, wordlist)
            else:
                print("Please select a wordlist, or deselect directory enumeration")

        for url in correctURLs:
            if doSQL.get() or doAll.get():
                test_sql(url)

            if doXSS.get() or doAll.get():
                test_xss(url)


def main():
    global report

    session = requests.Session()
    session.headers[
        'User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36'

    # collect all the args

    parser = argparse.ArgumentParser(
        prog='General Vulnerability Scanner',
        description='Scans for common vulnerabilities, incuding SQL, XSS and Wordpress version',
        epilog='')

    parser.add_argument("url")
    parser.add_argument('-d', '--direct',
                        action='store_true')
    parser.add_argument('-q', '--sql', action='store_true')
    parser.add_argument('-x', '--xss', action='store_true')
    parser.add_argument('-a', '--all', action='store_true')
    parser.add_argument('-p', '--wordpress', action='store_true')
    parser.add_argument('-w', '--wordlist')
    parser.add_argument('-g', '--gui', action=guiAction)

    args = parser.parse_args()

# Run everything selected

    DirectoryEnum = False
    if args.direct or args.all:
        DirectoryEnum = True

        wordlist = args.wordlist

    url = args.url
    correctURLs = [url] # array with just url, needed if directory enumeration is not selected

    if DirectoryEnum:
        if os.path.isfile(wordlist):

            correctURLs = directoryBust(url, wordlist)
        else:
            print("Please select a wordlist, or deselect directory enumeration")

    for url in correctURLs:
        if args.sql or args.all:
            test_sql(url)

        if args.xss or args.all:
            test_xss(url)

        if args.wordpress or args.all:
            wordpressEnum(url)

        if args.all:
            nmap(url)


    #contactUser(report)
    print(report)


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
        wrongOne = requests.post(url, {form.name: "wrongpass"})
        time.sleep(0.5)
        wrongTwo = requests.post(url, {form.name: "anotherwrongpass"})

        if wrongOne == wrongTwo:  # if these equal, it stands to reason all incorrect responses are
            technique = 1
        else:
            technique = 2  # assume that a technique worked if it takes more than the length between the tests to respond
            # may result in false positives or negatives

            greater = max(wrongOne.elapsed.total_seconds(), wrongTwo.elapsed.total_seconds())
            between = abs(wrongOne.elapsed.total_seconds() - wrongTwo.elapsed.total_seconds())

        if technique == 1:

            for injection in injections:
                attempt = requests.post(url, {form.name: injection})
                time.sleep(0.3)
                if attempt.text != wrongOne.text:
                    report = report + "Sql Injection suspected using:  " + injection + "\n"

        if technique == 2:
            for injection in injections:
                attempt = requests.post(url, {form.name: injection})
                time.sleep(0.3)

                if attempt.elapsed.total_seconds() > greater + (2 * between):
                    report = report + "Sql Injection Suspected using:  " + injection + "\n"

def nmap(url): # Nmaps site to get flags and dns scan
    global report
    nmap = nmap3.Nmap()

    baseURL = baseURl(url)

    results = nmap.nmap_dns_brute_script(baseURL)

    report = report + "Result of dns brute forcing" + results


def contactUser(content):
    webhook = DiscordWebhook(url="urltoserverwebhook", content=content)
    response = webhook.execute()



def wordpressEnum(url):
    global report
    r = requests.get(url)
    soup = BeautifulSoup.soup(r, "html.parser")

    version = soup.find_all('meta', name="generator")  # finds the generator tag
    if version[0].content.contains("Wordpress"):
        wpSys = requests.get(f'https://www.wpvulnerability.net/core/{version[0].content}/')

        report = report + "Generator tag open. Found vulnerabilities as follows: " + wpSys

    # Known wordpress extensions
    baseURL = baseURl(url)
    users = requests.get(baseURL + "wp-json/wp/v2/users")
    pages = requests.get(baseURL + "wp-json/wp/v2/pages")

    if users.status_code == 200:
        report = report + "\n Users page open, exposing: '" + users.text + "' to the public"
    if pages.status_code == 200:
        report = report + "\n Users page open, exposing: '" + pages.text + "' to the public"


def directoryBust(url, wordlist):

    # threading for speed

    baseURL = baseURl(url) # get base url

    correct = []

    with open(wordlist) as wl:
        for line in wl:
            r = requests.get(f'{baseURL}/{line}')

            if r.status_code == 200:
                correct.append(f'{baseURL}/{line}')

            time.sleep(0.2)  # What is minimum acceptable, may need just a short wordlist
    return correct

def test_xss(url):

    global report
    if url[:6] != "https://":
        url = f'https://{url}'

    # probably some easier way to check for correct execution and this is less efficient, but I wanted some practice with Selenium
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")

    os.environ['PATH'] += r'C:/Users/benja/Desktop/Selenium Drivers/chromedriver_win32'
    driver = webdriver.Chrome(options=options)


    driver.get(url)
    inputs = driver.find_elements(By.XPATH, "//input")

    injections = []
    with open('xss.txt') as my_file:
        for line in my_file:
            injections.append(line)

    for input in inputs:
        for inject in injections:
            try:

                input.send_keys(inject)
                wait = WebDriverWait(driver, 3).until(EC.alert_is_present()) # waits 3 sec for alert


                report += "Seems injection was allowed with this XXS injection: " + inject +"\n This occured in: " + input.name




            except(): # nothing happened
                pass



    driver.quit()








def baseURl(url): # quick utility function to get base url http://example.com/directory/sub/ -> https://example.com
    i = 0
    for char in url:  # probably some tricky way to do with string manipulation
        if char == "/":
            break
        else:
            i = i + 1  # code editor hates i++

    baseURL = url[:i]
    return baseURL


main()


