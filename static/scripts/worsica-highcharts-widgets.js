//HISTOGRAM
function addHistogramChart(divId, data, xAxisTitle, yAxisTitle){
	var chartDiv = "chart"+divId
	var tableId = "table"+divId

	var isInverted = false	
	
	console.log('----create chart-----')
	$("#"+tableId+" tr td").html("<div class='graph' id='"+chartDiv+"'></div>");
	hchart = Highcharts.chart(chartDiv,{
		chart: {
			height:200,
			type: 'column',
			backgroundColor: 'transparent', 
		},
		title: {
			text: 'Histogram'
		},
		subtitle: {
			text: ''
		},
		navigation: {
			buttonOptions: {
				enabled: false
			}
		},
		xAxis: {
			categories: data['rtbmetaCategories'],
			crosshair: true,
			title: { 
				text: xAxisTitle,
				style: {
					color: '#EEEEEE'
				}
			}, 
			labels: {
				style: {
					color: '#EEEEEE'
				}
			},
		},
		yAxis: {
			min: 0,
			title: { 
				text: yAxisTitle,
				style: {
					color: '#EEEEEE'
				}
			},
			labels: {
				style: {
					color: '#EEEEEE'
				}
			},
		},
		lang: {
			noData: "Sorry, no data available"
		},
		tooltip: {
			pointFormat: '<b>Number of pixels: {point.y}</b>',
			headerFormat: '<span style="font-size:12px">Pixel value: {point.key}</span><br>',
		},
		plotOptions: {
			column: {
				pointPadding: 0,
				borderWidth: 0,
				groupPadding: 0,
				shadow: false
			}
		},
		series: [{
			name: 'Pixels',
			data: data['rtbmetaValues'],
			label: { enabled: false },
			showInLegend: false,
			point: {
				events: {
					click: function (event) {
						$('#optThreshold-div-thr').val(this.category)
						$('#optThreshold-div-thr').change()
					}
				}
			}
		}]
	})

}


//================
//SPLINE
//divId: id of div where you want to allocate the chart
//data: JSON serie array of type [{'data': [[0,0,1.0],[0,1,3.0],...] }]
//================
function addSplineChart(divId, data, xAxisTitle, yAxisTitle){
	var chartDiv = "chart"+divId
	var tableId = "table"+divId

	var isInverted = false	
	
	console.log('----create chart-----')
	$("#"+tableId+" tr td").html("<div class='graph' id='"+chartDiv+"'></div>");
	
	hchart = Highcharts.chart(chartDiv, {
		chart: {  
	        zoomType: 'xy', 
			backgroundColor: 'transparent', 
			inverted: isInverted,
			reflow: false,
		},
		credits: {
			enabled: false
		},
		boost: {
			useGPUTranslations: true,
			//usePreallocated: true
		},
		title: { 
			text: '', 
			
		}, 
		subtitle: { 
			text: '',
		},
		legend: { 
			maxHeight: 80,
		},
		navigation: {
			buttonOptions: {
				enabled: false
			}
		},
		xAxis: {
			type: 'datetime', 
			title: { 
				text: xAxisTitle,
				style: {
					color: '#EEEEEE'
				}
			}, 
			labels: {
				style: {
					color: '#EEEEEE'
				}
			},
		},
		yAxis: { //if inverted, yAxis is X
			title: { 
				text: yAxisTitle,
				style: {
					color: '#EEEEEE'
				}
			},
			labels: {
				style: {
					color: '#EEEEEE'
				}
			},
			minPadding: 0,
			maxPadding: 0,
			startOnTick: false,
			endOnTick: false,
		},
		lang: {
			noData: "Sorry, no data available"
		},
		plotOptions: {
			series: {				
				label: { enabled: false },
				showInLegend: false
			},			
		},
		tooltip:{ animation: false, /**enabled:false*/ },	
		series: [{
			animation: false,
			boostThreshold: 1,
			turboThreshold: data.length+1,
			type: 'spline',				
			tooltip: {pointFormat: '<b>{point.y:.2f}m</b>'},
			data: data,
		}]
	});
	return hchart
}
