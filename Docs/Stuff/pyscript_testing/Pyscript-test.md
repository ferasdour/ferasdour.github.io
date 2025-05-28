---
publish: True
title: pyscript-test
---

<html>
<head>
<title> Nothing to see here </title>
<style> body{ margin: 0; } iframe{ display: block;  height: 100vh; width: 100vw;  border: none;  background: lightyellow; } </style>
</head>
<body>
<div id="content"></div>  
<script>  fetch('https://github.com/ferasdour/other-nonsense/blob/main/README.md')  
    .then(response => response.json())  
    .then(data => {  
      document.getElementById('content').innerHTML = `<p>${data.content}</p>`;  
    })  
    .catch(error => console.error('Error fetching data:', error));</script>
</body>
</html>
