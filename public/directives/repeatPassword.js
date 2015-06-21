angular.module('MyApp')
	.directive('repeatPassword', function () {
		return {
			require: 'ngModel',
			link: function (scope, elem, attrs, ctrl) {
				var otherInput = elem.inheritedData("$formController")[attrs.repeatPassword];

				ctrl.$parses.push(function (value) {
					if (value === otherInput.$viewValue) {
						ctrl.$setValidity('repeat', true);
						return value;
					}
					ctrl.$setValidity('repeat', false);
				});

				otherInput.$parses.push(function (value) {
					ctrl.$setValidity('repeat', value === ctrl.$viewValue);
				});
			}
		};
	});