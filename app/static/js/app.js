const sidebar = document.querySelector(".sidebar"); // Correctly select the first element with class "sidebar"

function toggleSubMenu(button) {
    const submenu = button.nextElementSibling;

    if (!submenu.classList.contains("show")) {
        closeAllSubMenus();
    }

    submenu.classList.toggle("show");
    button.classList.toggle("rotate");
}

function closeAllSubMenus() {
    sidebar.querySelectorAll(".show").forEach(ul => {
        ul.classList.remove("show");
        ul.previousElementSibling.classList.remove("rotate");
    });
}
