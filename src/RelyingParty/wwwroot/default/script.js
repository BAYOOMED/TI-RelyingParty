window.addEventListener('load', async (event) => {
    let data = await fetch('/idp');
    let idp = await data.json();
    let form = document.querySelector("form");
    idp.sort((a, b) => a.organization_name.toLowerCase().localeCompare(b.organization_name.toLowerCase()));
    idp.forEach(ele => {
        let template = document.createElement("template");
        template.innerHTML = `
            <button type="submit" value="${ele.id}" name="idpid" >
                <div><img src="${ele.logo_uri}" onerror="this.src='logo_missing.svg'" alt="logo"/></div><span>${ele.organization_name}</span>
            </button>`;
        form.appendChild(template.content);
    });

    document.getElementById("searchbar").addEventListener('input', () => {
        const searchTerm = document.getElementById("searchbar").value.toLowerCase();
        document.getElementsByName("idpid").forEach((element) => {
            const orgName = element.children[1].innerText.toLowerCase();
            element.hidden = !orgName.includes(searchTerm);
        });
    });
    document.getElementById("code").value = (new URLSearchParams(window.location.search)).get('code');
});
