function a(props) {
// ruleid: javascript.xss.react-dangerously-set
  return h("div", { dangerouslySetInnerHTML: { __html: props.bio } });
}


function b(props) {
// ok: javascript.xss.react-dangerously-set
  return h("div", { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(props.bio) } });
}
