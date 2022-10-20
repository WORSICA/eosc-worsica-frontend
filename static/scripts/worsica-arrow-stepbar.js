/*https://codepen.io/polinovskyi/pen/embZmw*/

$( document ).ready(function() {
		
		var	next = $(".next");
		var	steps = $(".step");
		
		next.bind("click", function() { 
			$.each( steps, function( i ) {
				if (!$(steps[i]).hasClass('current') && !$(steps[i]).hasClass('done')) {
					$(steps[i - 1]).removeClass('current').addClass('done');					
					$(steps[i]).addClass('current');
					return false;
				}
			})		
		});
	})