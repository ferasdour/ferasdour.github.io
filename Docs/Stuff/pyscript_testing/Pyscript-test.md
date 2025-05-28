---
publish: true
title: pyscript-test
---

<html>
<head>
<title> Nothing to see here </title>
<style> body{ margin: 0; } iframe{ display: block;  height: 100vh; width: 100vw;  border: none;  background: lightyellow; } </style>
</head>
<body>  
<div id="siteloader">
  <object id="object1" data="" />
</div>
<script >
$(function() {
  $("#object1").load(function() {
    $(this).contents().find("#lemail_id").val("lemail_id")
  });
  $("#object1").attr('data', 'https://github.com/ferasdour/other-nonsense/blob/main/README.md');
});
</script>
</body>
</html>
