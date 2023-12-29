$(document).ready(()=>{
    $('.btn_hide').on('click',e=>{
        $('.container').fadeToggle(500).toggleClass("hide_it");
        e.preventDefault();
    });
});

