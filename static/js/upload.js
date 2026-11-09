(function () {
  const dropzone = document.getElementById("dropzone");
  const input = document.getElementById("file-input");
  const fileList = document.getElementById("file-list");
  const form = document.getElementById("scan-form");
  const scanBtn = document.getElementById("scan-btn");

  function renderFileList() {
    if (!input.files || input.files.length === 0) {
      fileList.textContent = "";
      return;
    }
    const names = Array.from(input.files).map((f) => f.name);
    fileList.textContent = names.length <= 4
      ? names.join(", ")
      : `${names.slice(0, 4).join(", ")} +${names.length - 4} more`;
  }

  input.addEventListener("change", renderFileList);

  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      renderFileList();
    }
  });

  if (form) {
    form.addEventListener("submit", () => {
      scanBtn.disabled = true;
      scanBtn.textContent = "Scanning...";
    });
  }
})();
