import Link from "next/link";

import User from "./User";
import NavStyles from "./styles/NavStyles";

const Nav = () => (
  <NavStyles>
    <User>
      {({ data: { me } }) => {
        console.log(me);
        if (me) {
          return me.name;
        }
        return null;
      }}
    </User>
    <Link href="/items">
      <a>Shop</a>
    </Link>
    <Link href="/sell">
      <a>Sell</a>
    </Link>
    <Link href="/signup">
      <a>Signup</a>
    </Link>
    <Link href="/orders">
      <a>Orders</a>
    </Link>
    <Link href="/me">
      <a>Me</a>
    </Link>
  </NavStyles>
);

export default Nav;
