from .abc import ClientBase


class DatasetsApiClient(ClientBase):
    def get(self, dataset_id_or_slug: int | str) -> dict:
        """Get a single dataset"""
        url = "/api/v1/dataset"
        # Lookup by uuid not supported
        if isinstance(dataset_id_or_slug, str):
            url += f"?q=(filter:(col:uuid,opr:eq,value:'{dataset_id_or_slug}'))"
        else:
            url += f"/{dataset_id_or_slug}"

        res = self.session.get(url)
        res.raise_for_status()
        data = res.json()
        if isinstance(dataset_id_or_slug, str):
            if not data["result"]:
                raise ValueError(f"Dataset with uuid {dataset_id_or_slug} not found")
            return data["result"][0]
        return data

    def get_all(self) -> dict:
        """Get overview all datasets."""
        url = "/api/v1/dataset/"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def remove(self, dataset_id_or_slug: int | str) -> None:
        """Delete a dataset."""
        dataset = self.get(dataset_id_or_slug)
        res = self.session.delete(f"/api/v1/dataset/{dataset['id']}")
        res.raise_for_status()
