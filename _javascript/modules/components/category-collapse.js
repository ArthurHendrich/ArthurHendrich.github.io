
/**
 * Tab 'Categories' expand/close effect.
 */

import 'bootstrap/js/src/collapse.js';

const childPrefix = 'l_';
const parentPrefix = 'h_';
const children = document.getElementsByClassName('collapse');

export function categoryCollapse() {
  [...children].forEach((elem) => {
    const id = parentPrefix + elem.id.substring(childPrefix.length);
    const parent = document.getElementById(id);

    // collapse sub-categories
    elem.addEventListener('hide.bs.collapse', () => {
      if (parent) {
        const icon = parent.querySelector('.far.fa-folder-open');
        const arrow = parent.querySelector('.fas.fa-angle-down');
        
        icon.className = 'far fa-folder fa-fw';
        arrow.classList.add('rotate');
        parent.classList.remove('hide-border-bottom');
        
        // Add smooth transition
        icon.style.transition = 'all 0.3s ease';
        arrow.style.transition = 'transform 0.3s ease';
      }
    });

    // expand sub-categories
    elem.addEventListener('show.bs.collapse', () => {
      if (parent) {
        const icon = parent.querySelector('.far.fa-folder');
        const arrow = parent.querySelector('.fas.fa-angle-down');
        
        icon.className = 'far fa-folder-open fa-fw';
        arrow.classList.remove('rotate');
        parent.classList.add('hide-border-bottom');
        
        // Add smooth transition
        icon.style.transition = 'all 0.3s ease';
        arrow.style.transition = 'transform 0.3s ease';
      }
    });
  });
}
