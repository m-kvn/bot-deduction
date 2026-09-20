import json, time, sys
from patchright.sync_api import sync_playwright
url = "file:///" + __file__.replace("\\", "/").rsplit("/", 1)[0] + "/fill.html"
with sync_playwright() as p:
    b = p.chromium.launch(headless=False, channel="chrome")
    pg = b.new_page()
    pg.goto(url); time.sleep(1)
    pg.fill("input[name=name]", "Kavin Kumar")
    pg.fill("textarea[name=message]", "Following up on the bot-signal demo - could you share pricing?")
    time.sleep(0.8)
    log = pg.evaluate("() => document.documentElement.dataset.log")
    print("PATCHRIGHT fill():", log)
    pg.locator("input[name=name]").click()
    pg.keyboard.type("abc", delay=60)
    time.sleep(0.5)
    print("after real type():", pg.evaluate("() => document.documentElement.dataset.log"))
    b.close()
