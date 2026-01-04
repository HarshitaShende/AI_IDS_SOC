new Chart(document.getElementById("modelChart"),{
    type:"bar",
    data:{
        labels:["Logistic Reg","SVM","Random Forest","Your IDS"],
        datasets:[{
            label:"Accuracy (%)",
            data:[92,95,98,99.8],
            backgroundColor:"#2fa4ff"
        }]
    },
    options:{
        responsive:true,
        maintainAspectRatio:false,
        scales:{y:{beginAtZero:true,max:100}}
    }
});
