import src.network as network
from src import __version__


def test_version():
    assert __version__ == "0.1.0"


# Setup a demo router
router = network.Router()
router.add(
    network.Node(
        253, "03b078e55cbdf9a88a28f9771647ec710c8d44a3df31ac484cc3659fc3a66fee93",
    )
)
router.add(
    network.Node(
        254, "03445b25947da6d1adeed9dd4717691dde5d0d5bb7ebb294a20e4eef2850c0fa2d",
    )
)
router.add(
    network.Node(
        255, "0387e97648177eb1a03abc675d3df0a7a9a368324718b0f7c96ce992d2d0665aea",
    )
)
