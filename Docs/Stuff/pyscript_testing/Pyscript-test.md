---
publish: true
title: pyscript-test
---

<script >
fetch("https://github.com/ferasdour/other-nonsense/blob/main/README.md")
      .then(response => response.text())
      .then(data => document.getElementById('code').textContent = data)
</script>
