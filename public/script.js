
const rc = rough.canvas(document.getElementById('canvas'));

//line and rectangle

rc.circle(40, 70,80,  {
  fill: 'white',
  hachureAngle: -60, hachureGap: 10,
  stroke: 'white'
});
rc.circle(120, 90, 80,  {
  fill: '#96E6F5',
  hachureAngle: 60, hachureGap: 5,
  stroke: '#96E6F5'
});

// ellipse and circle
$('.ui.sticky')
  .sticky({
    context: '#content'
  })
;

$('.ui.sidebar')
  .sidebar('setting', 'transition', 'overlay')
  // .sidebar('toggle')
  .sidebar('attach events', '.open.button', 'show')
  .sidebar('setting','dimPage', false )
;

$('.ui.modal')
.modal('show')
;


$('.tool-tip').popup();

function uncheck() {
document.getElementById("red").checked = false;
}
$('.ui.dropdown')
  .dropdown()
;
$('.ui.checkbox')
.checkbox()
;
$('.menu .item')
.tab()
;

$('.accordion')
.accordion({
  selector: {
    trigger: '.title'
  }
})
;

$('#diacriticsexample')
    .search({
        ignoreDiacritics: true,
        fullTextSearch:'exact',
        source: [
            { title: 'André'},
            { title: 'Bokmål'},
            { title: 'café'},
            { title: 'cafetería'},
            { title: 'château'},
            { title: 'décolleté'},
            { title: 'Élysée'},
            { title: 'Fräulein'},
            { title: 'garçon'},
            { title: 'háček'},
            { title: 'inrō'},
            { title: 'jūjutsu'},
            { title: 'kroužek'},
            { title: 'La Niña'},
            { title: 'Māori'},
            { title: 'négligée'},
            { title: 'pączki'},
            { title: 'Québec'},
            { title: 'ragoût'},
            { title: 'Škoda'},
            { title: 'takahē'},
            { title: 'über'},
            { title: 'voilà'},
            { title: 'whekī'},
            { title: 'c Zoë'}
        ]
    })
;


