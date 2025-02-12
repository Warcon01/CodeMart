; (function () {

	'use strict';



	// iPad and iPod detection	
	var isiPad = function () {
		return (navigator.platform.indexOf("iPad") != -1);
	};

	var isiPhone = function () {
		return (
			(navigator.platform.indexOf("<i></i>Phone") != -1) ||
			(navigator.platform.indexOf("iPod") != -1)
		);
	};




	// Click outside of offcanvass
	var mobileMenuOutsideClick = function () {

		$(document).click(function (e) {
			var container = $("#fh5co-offcanvas, .js-fh5co-close-offcanvas");
			if (!container.is(e.target) && container.has(e.target).length === 0) {

				if ($('#fh5co-offcanvas').hasClass('animated fadeInLeft')) {

					$('#fh5co-offcanvas').addClass('animated fadeOutLeft');
					setTimeout(function () {
						$('#fh5co-offcanvas').css('display', 'none');
						$('#fh5co-offcanvas').removeClass('animated fadeOutLeft fadeInLeft');
					}, 1000);
					$('.js-fh5co-nav-toggle').removeClass('active');

				}


			}
		});

		$('body').on('click', '.js-fh5co-close-offcanvas', function (event) {


			$('#fh5co-offcanvas').addClass('animated fadeOutLeft');
			setTimeout(function () {
				$('#fh5co-offcanvas').css('display', 'none');
				$('#fh5co-offcanvas').removeClass('animated fadeOutLeft fadeInLeft');
			}, 1000);
			$('.js-fh5co-nav-toggle').removeClass('active');

			event.preventDefault();

		});

	};





	// Burger Menu
	var burgerMenu = function () {

		$('body').on('click', '.js-fh5co-nav-toggle', function (event) {

			var $this = $(this);

			$('#fh5co-offcanvas').css('display', 'block');
			setTimeout(function () {
				$('#fh5co-offcanvas').addClass('animated fadeInLeft');
			}, 100);

			// $('body').toggleClass('fh5co-overflow offcanvas-visible');
			$this.toggleClass('active');
			event.preventDefault();

		});

	};

	var scrolledWindow = function () {

		$(window).scroll(function () {

			var header = $('#fh5co-header'),
				scrlTop = $(this).scrollTop();


			$('#fh5co-home .flexslider .fh5co-overlay').css({
				'opacity': (.5) + (scrlTop / 2000)
			});

			if ($('body').hasClass('offcanvas-visible')) {
				$('body').removeClass('offcanvas-visible');
				$('.js-fh5co-nav-toggle').removeClass('active');
			}

		});

		$(window).resize(function () {
			if ($('body').hasClass('offcanvas-visible')) {
				$('body').removeClass('offcanvas-visible');
				$('.js-fh5co-nav-toggle').removeClass('active');
			}
		});

	};




	// Page Nav
	var clickMenu = function () {
		var topVal = ($(window).width() < 769) ? 0 : 58;

		$(window).resize(function () {
			topVal = ($(window).width() < 769) ? 0 : 58;
		});

		if ($(this).attr('href') != "#") {
			$('#fh5co-main-nav a:not([class="external"]), #fh5co-offcanvas a:not([class="external"])').click(function (event) {
				var section = $(this).data('nav-section');


				if ($('div[data-section="' + section + '"]').length) {

					$('html, body').animate({
						scrollTop: $('div[data-section="' + section + '"]').offset().top - topVal
					}, 500);

				}
				event.preventDefault();

			});
		}




	};


	var contentWayPoint = function () {
		var i = 0;
		$('.animate-box').waypoint(function (direction) {

			if (direction === 'down' && !$(this.element).hasClass('animated')) {

				i++;

				$(this.element).addClass('item-animate');
				setTimeout(function () {

					$('body .animate-box.item-animate').each(function (k) {
						var el = $(this);
						setTimeout(function () {
							el.addClass('fadeInUp animated');
							el.removeClass('item-animate');
						}, k * 200, 'easeInOutExpo');
					});

				}, 100);

			}

		}, { offset: '85%' });


	};


	// Document on load.
	$(function () {

		mobileMenuOutsideClick();
		burgerMenu();
		scrolledWindow();

		// Animations
		contentWayPoint();



	});
	function toggleDropdown() {
		document.getElementById('dropdown').classList.toggle('show');
	}

	function selectCity(city) {
		document.querySelector('.location-selector').textContent = city;
		document.getElementById('dropdown').classList.remove('show');
	}

	// Close the dropdown if the user clicks outside of it
	window.onclick = function (event) {
		if (!event.target.matches('.location-selector') && !event.target.matches('.location-option')) {
			var dropdowns = document.getElementsByClassName("dropdown-content");
			for (var i = 0; i < dropdowns.length; i++) {
				var openDropdown = dropdowns[i];
				if (openDropdown.classList.contains('show')) {
					openDropdown.classList.remove('show');
				}
			}
		}
	}
	let basket = [];
	let total = 0;

	function updateBasket() {
		const basketItems = document.getElementById('basket-items');
		const basketCount = document.getElementById('basket-count');
		const basketTotal = document.getElementById('basket-total');

		basketItems.innerHTML = '';
		basket.forEach(item => {
			const itemElement = document.createElement('div');
			itemElement.className = 'basket-item';
			itemElement.innerHTML = `
					<span>${item.name}</span>
					<span>${item.price}₸</span>
				`;
			basketItems.appendChild(itemElement);
		});

		basketCount.textContent = basket.length;
		basketTotal.textContent = `${total}₸`;
	}

	function toggleBasket() {
		const basketDropdown = document.getElementById('basket-dropdown');
		basketDropdown.classList.toggle('show');
	}

	document.querySelectorAll('.add-to-basket').forEach(button => {
		button.addEventListener('click', () => {
			const name = button.getAttribute('data-name');
			const price = parseInt(button.getAttribute('data-price'));
			basket.push({ name, price });
			total += price;
			updateBasket();
		});
	});
	function toggleDropdown() {
		var dropdown = document.getElementById('city-dropdown');
		dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
	}
	function selectCity(city) {
		document.getElementById('selected-city').textContent = city;
		document.getElementById('city-dropdown').style.display = 'none';
	}

}());